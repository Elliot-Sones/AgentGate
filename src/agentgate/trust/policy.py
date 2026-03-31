from __future__ import annotations

from dataclasses import dataclass

from agentgate.trust.models import (
    TrustFinding,
    TrustSeverity,
    TrustVerdict,
    severity_counts,
    verdict_rank,
)
from agentgate.trust.signals import SignalContext, is_strong_evidence


@dataclass
class TrustPolicy:
    version: str = "trust-policy-v2"

    def verdict_for_findings(self, findings: list[TrustFinding]) -> TrustVerdict:
        failed = [finding for finding in findings if not finding.passed]
        if not failed:
            return TrustVerdict.ALLOW_CLEAN

        has_block_evidence = False
        has_manual_review_evidence = False
        has_warnings = False
        strong_high_families: set[str] = set()

        for finding in failed:
            context = finding.context if isinstance(finding.context, SignalContext) else SignalContext()
            strong = is_strong_evidence(context)
            family = _check_family(finding.check_id)

            if finding.severity == TrustSeverity.CRITICAL:
                if finding.legacy_interpretation:
                    has_manual_review_evidence = True
                elif strong:
                    has_block_evidence = True
                else:
                    has_manual_review_evidence = True
            elif finding.severity == TrustSeverity.HIGH:
                if strong:
                    has_manual_review_evidence = True
                    strong_high_families.add(family)
                else:
                    has_warnings = True
            elif finding.severity == TrustSeverity.MEDIUM:
                has_warnings = True

        if not has_block_evidence:
            legacy_criticals = [
                finding
                for finding in failed
                if finding.severity == TrustSeverity.CRITICAL and finding.legacy_interpretation
            ]
            for legacy in legacy_criticals:
                legacy_family = _check_family(legacy.check_id)
                if strong_high_families - {legacy_family}:
                    has_block_evidence = True
                    break

        if has_block_evidence:
            return TrustVerdict.BLOCK
        if has_manual_review_evidence:
            return TrustVerdict.MANUAL_REVIEW
        if has_warnings:
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


def _check_family(check_id: str) -> str:
    if check_id.startswith("static_"):
        return f"static_{check_id}"
    if check_id.startswith("runtime_"):
        return f"runtime_{check_id}"
    return check_id
