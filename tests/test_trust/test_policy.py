from __future__ import annotations

from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity, TrustVerdict
from agentgate.trust.policy import TrustPolicy
from agentgate.trust.signals import SignalContext


def _finding(
    severity: TrustSeverity,
    *,
    evidence: str = "heuristic",
    confidence: str = "high",
    reachability: str = "on_execution_path",
    passed: bool = False,
    legacy: bool = False,
    check_id: str = "test_check",
) -> TrustFinding:
    context = SignalContext(
        evidence_strength=evidence,
        attribution_confidence=confidence,
        reachability=reachability,
    )
    return TrustFinding(
        check_id=check_id,
        title="Test",
        category=TrustCategory.HIDDEN_BEHAVIOR,
        severity=severity,
        passed=passed,
        summary="test",
        context=None if legacy else context,
        legacy_interpretation=legacy,
    )


def test_critical_strong_evidence_blocks() -> None:
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.CRITICAL, evidence="procfs_confirmed")]
    assert policy.verdict_for_findings(findings) == TrustVerdict.BLOCK


def test_critical_weak_evidence_manual_review() -> None:
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.CRITICAL, evidence="log_only", confidence="low")]
    assert policy.verdict_for_findings(findings) == TrustVerdict.MANUAL_REVIEW


def test_critical_heuristic_on_path_high_confidence_blocks() -> None:
    policy = TrustPolicy()
    findings = [
        _finding(
            TrustSeverity.CRITICAL,
            evidence="heuristic",
            confidence="high",
            reachability="on_execution_path",
        )
    ]
    assert policy.verdict_for_findings(findings) == TrustVerdict.BLOCK


def test_critical_heuristic_low_confidence_manual_review() -> None:
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.CRITICAL, evidence="heuristic", confidence="low")]
    assert policy.verdict_for_findings(findings) == TrustVerdict.MANUAL_REVIEW


def test_high_strong_manual_review() -> None:
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.HIGH, evidence="procfs_confirmed")]
    assert policy.verdict_for_findings(findings) == TrustVerdict.MANUAL_REVIEW


def test_high_weak_allow_with_warnings() -> None:
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.HIGH, evidence="log_only", confidence="low")]
    assert policy.verdict_for_findings(findings) == TrustVerdict.ALLOW_WITH_WARNINGS


def test_medium_allow_with_warnings() -> None:
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.MEDIUM)]
    assert policy.verdict_for_findings(findings) == TrustVerdict.ALLOW_WITH_WARNINGS


def test_info_only_allow_clean() -> None:
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.INFO)]
    assert policy.verdict_for_findings(findings) == TrustVerdict.ALLOW_CLEAN


def test_low_only_allow_clean() -> None:
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.LOW)]
    assert policy.verdict_for_findings(findings) == TrustVerdict.ALLOW_CLEAN


def test_legacy_single_critical_cannot_block() -> None:
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.CRITICAL, legacy=True)]
    assert policy.verdict_for_findings(findings) == TrustVerdict.MANUAL_REVIEW


def test_legacy_critical_with_corroboration_blocks() -> None:
    policy = TrustPolicy()
    legacy = _finding(TrustSeverity.CRITICAL, legacy=True, check_id="static_manifest")
    corroborating = _finding(
        TrustSeverity.HIGH,
        evidence="procfs_confirmed",
        check_id="runtime_egress",
    )
    findings = [legacy, corroborating]
    assert policy.verdict_for_findings(findings) == TrustVerdict.BLOCK


def test_legacy_critical_with_same_check_does_not_block() -> None:
    policy = TrustPolicy()
    legacy = _finding(TrustSeverity.CRITICAL, legacy=True, check_id="static_manifest")
    same_check = _finding(
        TrustSeverity.HIGH,
        evidence="procfs_confirmed",
        check_id="static_manifest",
    )
    findings = [legacy, same_check]
    assert policy.verdict_for_findings(findings) == TrustVerdict.MANUAL_REVIEW


def test_passed_findings_ignored() -> None:
    policy = TrustPolicy()
    passed = TrustFinding(
        check_id="test",
        title="OK",
        category=TrustCategory.HIDDEN_BEHAVIOR,
        severity=TrustSeverity.CRITICAL,
        passed=True,
        summary="all good",
    )
    assert policy.verdict_for_findings([passed]) == TrustVerdict.ALLOW_CLEAN


def test_no_findings_allow_clean() -> None:
    policy = TrustPolicy()
    assert policy.verdict_for_findings([]) == TrustVerdict.ALLOW_CLEAN


def test_should_fail_thresholds() -> None:
    policy = TrustPolicy()
    assert policy.should_fail(TrustVerdict.BLOCK, "block") is True
    assert policy.should_fail(TrustVerdict.MANUAL_REVIEW, "block") is False
    assert policy.should_fail(TrustVerdict.MANUAL_REVIEW, "manual_review") is True
    assert policy.should_fail(TrustVerdict.ALLOW_WITH_WARNINGS, "allow_with_warnings") is True
