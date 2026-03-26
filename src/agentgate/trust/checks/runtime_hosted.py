from __future__ import annotations

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity
from agentgate.trust.runtime.hosted_runner import HostedRuntimeRunner


class HostedRuntimeCheck(BaseTrustCheck):
    check_id = "runtime_hosted"
    description = (
        "Probes the live hosted agent and collects runtime telemetry from its deployment context."
    )

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        findings: list[TrustFinding] = []

        if ctx.manifest is None and not ctx.manifest_error and ctx.manifest_path is not None:
            ctx.load_manifest()

        if ctx.source_dir is not None:
            ctx.infer_runtime_config_from_source()

        if ctx.config.dependency_validation_errors:
            return [
                self.finding(
                    title="Runtime dependency declaration blocked",
                    category=TrustCategory.RUNTIME_INTEGRITY,
                    severity=TrustSeverity.CRITICAL,
                    passed=False,
                    summary=" ".join(ctx.config.dependency_validation_errors),
                    recommendation=(
                        "Declare only approved dependency services and fix manifest "
                        "dependency/runtime_env structure before running runtime checks."
                    ),
                )
            ]

        if not ctx.config.hosted_url:
            return [
                self.finding(
                    title="Hosted runtime target missing",
                    category=TrustCategory.RUNTIME_INTEGRITY,
                    severity=TrustSeverity.HIGH,
                    passed=False,
                    summary="Hosted trust checks require a live agent URL.",
                    recommendation="Run trust-scan with --url pointing at the deployed agent endpoint.",
                )
            ]

        if not ctx.config.collect_runtime_traces:
            return [
                self.finding(
                    title="Hosted runtime collection disabled",
                    category=TrustCategory.RUNTIME_INTEGRITY,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary="Runtime trace collection disabled by configuration.",
                )
            ]

        runner = HostedRuntimeRunner(
            base_url=ctx.config.hosted_url,
            runtime_seconds=ctx.config.runtime_seconds,
            railway_workspace_dir=ctx.config.railway_workspace_dir,
            railway_service=ctx.config.railway_service,
            railway_environment=ctx.config.railway_environment,
            railway_project_token=ctx.config.railway_project_token,
            probe_paths=(
                list(ctx.generated_runtime_profile.probe_paths)
                if ctx.generated_runtime_profile is not None
                else None
            ),
            adaptive_api_key=(ctx.config.anthropic_api_key if ctx.config.adaptive_trust else ""),
            adaptive_model=ctx.config.adaptive_trust_model,
            source_dir=ctx.source_dir,
            manifest=ctx.manifest,
            static_findings=[],
        )
        trace = runner.run_profile(
            profile="hosted",
            canary_profile=ctx.config.canary_profile,
            artifact_dir=ctx.artifact_dir,
        )
        ctx.runtime_traces["hosted"] = trace
        if runner.runtime_context:
            ctx.hosted_runtime_context.update(runner.runtime_context)

        if trace.status == "ok":
            summary_parts = [
                f"Probed hosted agent at '{ctx.config.hosted_url}'.",
                f"Captured {len(trace.probe_responses)} probe response(s).",
            ]
            if trace.dependency_services:
                summary_parts.append(
                    "Observed deployment-backed dependencies: "
                    + ", ".join(trace.dependency_services)
                    + "."
                )
            findings.append(
                self.finding(
                    title="Hosted runtime profile executed",
                    category=TrustCategory.RUNTIME_INTEGRITY,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary=" ".join(summary_parts),
                )
            )
        else:
            findings.append(
                self.finding(
                    title="Hosted runtime profile error",
                    category=TrustCategory.RUNTIME_INTEGRITY,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary=trace.error or "Hosted runtime profile did not complete cleanly.",
                    recommendation="Review hosted URL reachability and Railway deployment logs.",
                )
            )
        return findings
