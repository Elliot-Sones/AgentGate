from __future__ import annotations

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity
from agentgate.trust.runtime.docker_runner import DockerRunner


class RuntimeSandboxCheck(BaseTrustCheck):
    check_id = "runtime_sandbox"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        findings: list[TrustFinding] = []

        if not ctx.config.collect_runtime_traces:
            return [
                self.finding(
                    title="Runtime detonation disabled",
                    category=TrustCategory.SANDBOX_EVASION,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary="Runtime trace collection disabled by configuration.",
                )
            ]

        runner = DockerRunner(
            image_ref=ctx.config.image_ref,
            runtime_seconds=ctx.config.runtime_seconds,
            enable_http_probing=ctx.config.enable_http_probing,
        )

        ok, err = runner.inspect_image()
        if not ok:
            findings.append(
                self.finding(
                    title="Container image inspection failed",
                    category=TrustCategory.SANDBOX_EVASION,
                    severity=TrustSeverity.HIGH,
                    passed=False,
                    summary=err or "Unable to inspect container image.",
                    recommendation="Ensure image is present and runtime environment has docker access.",
                )
            )
            return findings

        profiles: list[tuple[str, str]] = []
        mode = ctx.config.profile
        if mode in {"review", "both"}:
            profiles.append(("review", ctx.config.review_network_mode))
        if mode in {"prodlike", "both"}:
            profiles.append(("prodlike", ctx.config.prod_network_mode))

        for profile_name, network_mode in profiles:
            trace = runner.run_profile(
                profile=profile_name,
                network_mode=network_mode,
                canary_profile=ctx.config.canary_profile,
                artifact_dir=ctx.artifact_dir,
            )
            ctx.runtime_traces[profile_name] = trace

            if trace.status in ("ok", "timeout"):
                summary_parts = [
                    f"Captured {len(trace.network_destinations)} destination(s), "
                    f"{len(trace.tool_calls)} tool call marker(s)."
                ]
                if trace.status == "timeout":
                    summary_parts.append(
                        "Process timed out (expected for web servers)."
                    )
                findings.append(
                    self.finding(
                        title=f"Runtime sandbox profile executed: {profile_name}",
                        category=TrustCategory.SANDBOX_EVASION,
                        severity=TrustSeverity.INFO,
                        passed=True,
                        summary=" ".join(summary_parts),
                    )
                )
            else:
                findings.append(
                    self.finding(
                        title=f"Runtime sandbox profile error: {profile_name}",
                        category=TrustCategory.SANDBOX_EVASION,
                        severity=TrustSeverity.MEDIUM,
                        passed=False,
                        summary=trace.error or "Runtime profile did not complete cleanly.",
                        recommendation="Review runtime logs for execution or anti-analysis behavior.",
                    )
                )

        return findings
