from __future__ import annotations

import logging
import time

from agentgate.trust.checks import BaseTrustCheck, default_trust_checks
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext
from agentgate.trust.integrations.agentdojo_runner import AgentDojoRunner
from agentgate.trust.models import (
    EvidenceRef,
    TrustCategory,
    TrustFinding,
    TrustScanResult,
    TrustScorecard,
    TrustSeverity,
)
from agentgate.trust.policy import TrustPolicy

logger = logging.getLogger(__name__)


class TrustScanner:
    """Phase 2 scanner for agent trust and malware-style analysis."""

    def __init__(
        self,
        config: TrustScanConfig,
        checks: list[BaseTrustCheck] | None = None,
        policy: TrustPolicy | None = None,
    ) -> None:
        self.config = config
        self.checks = checks or default_trust_checks()
        self.policy = policy or TrustPolicy(version=config.policy_version)

    async def run(self) -> TrustScanResult:
        start = time.monotonic()
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self.config.load_allowlist()

        ctx = TrustScanContext(config=self.config)

        findings: list[TrustFinding] = []
        checks_failed = 0

        for check in self.checks:
            try:
                check_findings = await check.run(ctx)
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception("Trust check failed unexpectedly: %s", check.check_id)
                check_findings = [
                    TrustFinding(
                        check_id=check.check_id,
                        title="Trust check execution error",
                        category=TrustCategory.HIDDEN_BEHAVIOR,
                        severity=TrustSeverity.HIGH,
                        passed=False,
                        summary=f"Check '{check.check_id}' raised an exception: {exc}",
                        recommendation="Inspect check implementation and rerun.",
                    )
                ]

            findings.extend(check_findings)
            if any(not f.passed for f in check_findings):
                checks_failed += 1

        # Optional AgentDojo bridge
        dojo_findings = AgentDojoRunner().run(self.config.agentdojo_suite)
        findings.extend(dojo_findings)
        if dojo_findings and any(not f.passed for f in dojo_findings):
            checks_failed += 1

        checks_run = len(self.checks) + (1 if self.config.agentdojo_suite else 0)
        checks_passed = max(checks_run - checks_failed, 0)

        verdict = self.policy.verdict_for_findings(findings)
        counts = self.policy.summary_counts(findings)

        duration = time.monotonic() - start
        scorecard = TrustScorecard(
            checks_run=checks_run,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            findings_total=len(findings),
            findings_by_severity=counts,
            verdict=verdict,
            duration_seconds=round(duration, 3),
            policy_version=self.policy.version,
        )

        artifacts_manifest = [
            EvidenceRef.from_path("artifact", p, "Trust scan artifact") for p in ctx.artifacts
        ]

        metadata = {
            "image_ref": self.config.image_ref,
            "source_dir": str(self.config.source_dir) if self.config.source_dir else "",
            "manifest_path": str(self.config.manifest_path) if self.config.manifest_path else "",
            "profiles": self._profiles_used(),
            "egress_allowlist_size": len(self.config.egress_allowlist),
            "runtime_seconds": self.config.runtime_seconds,
            "canary_profile": self.config.canary_profile,
        }

        return TrustScanResult(
            scorecard=scorecard,
            findings=findings,
            metadata=metadata,
            artifacts_manifest=artifacts_manifest,
        )

    def _profiles_used(self) -> list[str]:
        if self.config.profile == "both":
            return ["review", "prodlike"]
        return [self.config.profile]
