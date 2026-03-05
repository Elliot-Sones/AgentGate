from __future__ import annotations

from dataclasses import dataclass

from agentgate.trust.models import (
    TrustFinding,
    TrustSeverity,
    TrustVerdict,
    severity_counts,
    verdict_rank,
)


@dataclass
class TrustPolicy:
    version: str = "trust-policy-v1"

    def verdict_for_findings(self, findings: list[TrustFinding]) -> TrustVerdict:
        def has(severity: TrustSeverity) -> bool:
            return any((not f.passed) and f.severity == severity for f in findings)

        if has(TrustSeverity.CRITICAL):
            return TrustVerdict.BLOCK
        if has(TrustSeverity.HIGH):
            return TrustVerdict.MANUAL_REVIEW
        if has(TrustSeverity.MEDIUM):
            return TrustVerdict.ALLOW_WITH_WARNINGS
        if has(TrustSeverity.LOW):
            return TrustVerdict.ALLOW_WITH_WARNINGS
        return TrustVerdict.ALLOW_CLEAN

    def should_fail(self, verdict: TrustVerdict, fail_on: str) -> bool:
        threshold = _parse_fail_on(fail_on)
        return verdict_rank(verdict) >= verdict_rank(threshold)

    def summary_counts(self, findings: list[TrustFinding]) -> dict[str, int]:
        return severity_counts(findings)


FAIL_ON_VALUES = {
    "allow_with_warnings": TrustVerdict.ALLOW_WITH_WARNINGS,
    "manual_review": TrustVerdict.MANUAL_REVIEW,
    "block": TrustVerdict.BLOCK,
}


def _parse_fail_on(value: str) -> TrustVerdict:
    return FAIL_ON_VALUES.get(value, TrustVerdict.BLOCK)
