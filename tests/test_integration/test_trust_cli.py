from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from agentgate.cli import cli
from agentgate.trust.models import (
    TrustCategory,
    TrustFinding,
    TrustScanResult,
    TrustScorecard,
    TrustSeverity,
    TrustVerdict,
)


def _make_result(verdict: TrustVerdict) -> TrustScanResult:
    finding = TrustFinding(
        check_id="test",
        title="sample",
        category=TrustCategory.EGRESS,
        severity=TrustSeverity.HIGH if verdict != TrustVerdict.ALLOW_CLEAN else TrustSeverity.INFO,
        passed=verdict == TrustVerdict.ALLOW_CLEAN,
        summary="summary",
    )
    return TrustScanResult(
        scorecard=TrustScorecard(
            checks_run=1,
            checks_passed=1 if verdict == TrustVerdict.ALLOW_CLEAN else 0,
            checks_failed=0 if verdict == TrustVerdict.ALLOW_CLEAN else 1,
            findings_total=1,
            findings_by_severity={
                "critical": 0,
                "high": 1 if verdict != TrustVerdict.ALLOW_CLEAN else 0,
                "medium": 0,
                "low": 0,
                "info": 1 if verdict == TrustVerdict.ALLOW_CLEAN else 0,
            },
            verdict=verdict,
            duration_seconds=0.1,
            policy_version="trust-policy-v1",
        ),
        findings=[finding],
        metadata={},
        artifacts_manifest=[],
    )


def test_trust_scan_exit_code_1_when_threshold_met() -> None:
    runner = CliRunner()
    mock_result = _make_result(TrustVerdict.MANUAL_REVIEW)

    def _run_stub(coro):
        coro.close()
        return mock_result

    with patch("agentgate.cli.asyncio.run", side_effect=_run_stub):
        result = runner.invoke(
            cli,
            [
                "trust-scan",
                "--image",
                "example:latest",
                "--format",
                "terminal",
                "--quiet",
                "--fail-on",
                "manual_review",
            ],
        )
    assert result.exit_code == 1


def test_trust_scan_exit_code_0_when_below_threshold() -> None:
    runner = CliRunner()
    mock_result = _make_result(TrustVerdict.ALLOW_CLEAN)

    def _run_stub(coro):
        coro.close()
        return mock_result

    with patch("agentgate.cli.asyncio.run", side_effect=_run_stub):
        result = runner.invoke(
            cli,
            [
                "trust-scan",
                "--image",
                "example:latest",
                "--format",
                "terminal",
                "--quiet",
                "--fail-on",
                "block",
            ],
        )
    assert result.exit_code == 0
