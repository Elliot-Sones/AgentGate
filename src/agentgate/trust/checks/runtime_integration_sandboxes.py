from __future__ import annotations

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity
from agentgate.trust.runtime.integration_sandboxes import (
    IntegrationExerciseResult,
    run_integration_sandbox_exercises,
)


class RuntimeIntegrationSandboxesCheck(BaseTrustCheck):
    check_id = "runtime_integration_sandboxes"
    description = (
        "Exercises managed external integration sandboxes such as Slack and Shopify "
        "against the live hosted agent when those integrations are declared and ready."
    )

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        findings: list[TrustFinding] = []
        profile = ctx.generated_runtime_profile
        sandboxes = list(getattr(profile, "integration_sandboxes", []) or []) if profile else []

        if not sandboxes:
            return [
                self.finding(
                    title="No managed external sandbox integrations were exercised",
                    category=TrustCategory.RUNTIME_INTEGRITY,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary="The submission did not declare any supported sandbox-backed external integrations.",
                )
            ]

        if not ctx.config.hosted_url:
            return [
                self.finding(
                    title="Hosted URL missing for sandbox integration testing",
                    category=TrustCategory.RUNTIME_INTEGRITY,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary="Sandbox-backed integration exercises require a live hosted agent URL.",
                    recommendation="Deploy the submission first so AgentGate can replay Slack/Shopify sandbox events.",
                )
            ]

        results = run_integration_sandbox_exercises(
            hosted_url=ctx.config.hosted_url,
            runtime_profile=profile,
            timeout_seconds=max(min(ctx.config.runtime_seconds, 20), 5),
        )
        ctx.hosted_runtime_context["integration_sandbox_results"] = [
            result.as_dict() for result in results
        ]

        for result in results:
            findings.extend(self._result_findings(result))

        if not findings:
            findings.append(
                self.finding(
                    title="No managed external sandbox integrations were exercised",
                    category=TrustCategory.RUNTIME_INTEGRITY,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary="AgentGate did not execute any Slack/Shopify sandbox scenarios in this run.",
                )
            )
        return findings

    def _result_findings(self, result: IntegrationExerciseResult) -> list[TrustFinding]:
        if result.status == "passed":
            return [
                self.finding(
                    title=f"{result.integration.title()} sandbox workflow executed",
                    category=TrustCategory.RUNTIME_INTEGRITY,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary=result.summary,
                    observed=" | ".join(result.evidence),
                )
            ]

        if result.status == "failed":
            severity = TrustSeverity.MEDIUM if result.ready else TrustSeverity.HIGH
            return [
                self.finding(
                    title=f"{result.integration.title()} sandbox workflow failed",
                    category=TrustCategory.RUNTIME_INTEGRITY,
                    severity=severity,
                    passed=False,
                    summary=result.summary,
                    recommendation=(
                        "Provide a reachable integration callback route and complete the managed "
                        "sandbox configuration before rerunning the trust scan."
                    ),
                    observed=" | ".join(result.evidence or result.notes),
                )
            ]

        return [
            self.finding(
                title=f"{result.integration.title()} sandbox workflow skipped",
                category=TrustCategory.RUNTIME_INTEGRITY,
                severity=TrustSeverity.INFO,
                passed=True,
                summary=result.summary or "No executable sandbox workflow was available.",
                observed=" | ".join(result.notes),
            )
        ]
