"""Tests for CLI options."""

from __future__ import annotations

from unittest.mock import patch
from click.testing import CliRunner

from agentgate.cli import cli
from agentgate.models.score import DetectorSummary, LetterGrade, ScoreCard
from agentgate.scanner import ScanResult


def _make_scan_result(pass_rate: float) -> ScanResult:
    """Create a ScanResult with a given pass rate."""
    total = 100
    passed = int(total * pass_rate)
    failed = total - passed

    return ScanResult(
        scorecard=ScoreCard(
            grade=LetterGrade.from_pass_rate(pass_rate),
            total_tests_run=total,
            total_tests_passed=passed,
            total_tests_failed=failed,
            pass_rate=pass_rate,
            detectors=[
                DetectorSummary(
                    name="prompt_injection",
                    tests_run=total,
                    tests_passed=passed,
                    tests_failed=failed,
                    failed_tests=[],
                ),
            ],
        ),
        results_by_detector={},
        duration=1.0,
    )


def _run_stub_factory(mock_result: ScanResult):
    def _run_stub(coro):
        coro.close()
        return mock_result

    return _run_stub


class TestFailBelow:
    def test_exit_code_1_when_below_threshold(self) -> None:
        runner = CliRunner()
        mock_result = _make_scan_result(0.8)

        with patch("agentgate.cli.asyncio.run", side_effect=_run_stub_factory(mock_result)):
            result = runner.invoke(
                cli,
                ["scan", "http://test:8000", "--fail-below", "0.9", "--quiet", "--format", "terminal"],
            )
        assert result.exit_code == 1

    def test_exit_code_0_when_above_threshold(self) -> None:
        runner = CliRunner()
        mock_result = _make_scan_result(0.95)

        with patch("agentgate.cli.asyncio.run", side_effect=_run_stub_factory(mock_result)):
            result = runner.invoke(
                cli,
                ["scan", "http://test:8000", "--fail-below", "0.9", "--quiet", "--format", "terminal"],
            )
        assert result.exit_code == 0

    def test_no_fail_below_always_exits_0(self) -> None:
        runner = CliRunner()
        mock_result = _make_scan_result(0.5)

        with patch("agentgate.cli.asyncio.run", side_effect=_run_stub_factory(mock_result)):
            result = runner.invoke(
                cli,
                ["scan", "http://test:8000", "--quiet", "--format", "terminal"],
            )
        assert result.exit_code == 0


class TestQuietMode:
    def test_quiet_suppresses_output(self) -> None:
        runner = CliRunner()
        mock_result = _make_scan_result(1.0)

        with patch("agentgate.cli.asyncio.run", side_effect=_run_stub_factory(mock_result)):
            result = runner.invoke(
                cli,
                ["scan", "http://test:8000", "--quiet", "--format", "terminal"],
            )
        # In quiet mode with terminal format, no terminal output should be rendered
        assert "AgentGate" not in result.output
