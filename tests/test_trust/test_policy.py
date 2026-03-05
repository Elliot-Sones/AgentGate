from __future__ import annotations

from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity, TrustVerdict
from agentgate.trust.policy import TrustPolicy


def _finding(severity: TrustSeverity, passed: bool = False) -> TrustFinding:
    return TrustFinding(
        check_id="test_check",
        title="test finding",
        category=TrustCategory.HIDDEN_BEHAVIOR,
        severity=severity,
        passed=passed,
        summary="summary",
    )


def test_policy_blocks_on_critical() -> None:
    policy = TrustPolicy()
    verdict = policy.verdict_for_findings([_finding(TrustSeverity.CRITICAL)])
    assert verdict == TrustVerdict.BLOCK


def test_policy_manual_review_on_high() -> None:
    policy = TrustPolicy()
    verdict = policy.verdict_for_findings([_finding(TrustSeverity.HIGH)])
    assert verdict == TrustVerdict.MANUAL_REVIEW


def test_policy_allow_with_warnings_on_medium() -> None:
    policy = TrustPolicy()
    verdict = policy.verdict_for_findings([_finding(TrustSeverity.MEDIUM)])
    assert verdict == TrustVerdict.ALLOW_WITH_WARNINGS


def test_policy_allow_clean_when_no_failed_findings() -> None:
    policy = TrustPolicy()
    verdict = policy.verdict_for_findings([_finding(TrustSeverity.INFO, passed=True)])
    assert verdict == TrustVerdict.ALLOW_CLEAN


def test_fail_on_thresholds() -> None:
    policy = TrustPolicy()
    assert policy.should_fail(TrustVerdict.BLOCK, "block") is True
    assert policy.should_fail(TrustVerdict.MANUAL_REVIEW, "block") is False
    assert policy.should_fail(TrustVerdict.MANUAL_REVIEW, "manual_review") is True
    assert policy.should_fail(TrustVerdict.ALLOW_WITH_WARNINGS, "allow_with_warnings") is True
