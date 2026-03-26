"""Tests for CLI options."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
from click.testing import CliRunner

from agentgate.cli import cli
from agentgate.models.score import DetectorSummary, LetterGrade, ScoreCard
from agentgate.scanner import ScanResult
from agentgate.trust.models import (
    TrustCategory,
    TrustFinding,
    TrustScanResult,
    TrustScorecard,
    TrustSeverity,
    TrustVerdict,
)
from agentgate.trust.runtime.railway_executor import RailwayExecutionResult


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


def _make_trust_result(verdict: TrustVerdict) -> TrustScanResult:
    finding = TrustFinding(
        check_id="runtime_hosted",
        title="hosted",
        category=TrustCategory.RUNTIME_INTEGRITY,
        severity=TrustSeverity.INFO
        if verdict == TrustVerdict.ALLOW_CLEAN
        else TrustSeverity.MEDIUM,
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
                "high": 0,
                "medium": 0 if verdict == TrustVerdict.ALLOW_CLEAN else 1,
                "low": 0,
                "info": 1 if verdict == TrustVerdict.ALLOW_CLEAN else 0,
            },
            verdict=verdict,
            duration_seconds=1.0,
            policy_version="trust-policy-v1",
        ),
        findings=[finding],
        metadata={},
        artifacts_manifest=[],
    )


class TestFailBelow:
    def test_exit_code_1_when_below_threshold(self) -> None:
        runner = CliRunner()
        mock_result = _make_scan_result(0.8)

        with patch("agentgate.cli.asyncio.run", side_effect=_run_stub_factory(mock_result)):
            result = runner.invoke(
                cli,
                [
                    "security-scan",
                    "http://test:8000",
                    "--fail-below",
                    "0.9",
                    "--quiet",
                    "--format",
                    "terminal",
                ],
            )
        assert result.exit_code == 1

    def test_exit_code_0_when_above_threshold(self) -> None:
        runner = CliRunner()
        mock_result = _make_scan_result(0.95)

        with patch("agentgate.cli.asyncio.run", side_effect=_run_stub_factory(mock_result)):
            result = runner.invoke(
                cli,
                [
                    "security-scan",
                    "http://test:8000",
                    "--fail-below",
                    "0.9",
                    "--quiet",
                    "--format",
                    "terminal",
                ],
            )
        assert result.exit_code == 0

    def test_no_fail_below_always_exits_0(self) -> None:
        runner = CliRunner()
        mock_result = _make_scan_result(0.5)

        with patch("agentgate.cli.asyncio.run", side_effect=_run_stub_factory(mock_result)):
            result = runner.invoke(
                cli,
                ["security-scan", "http://test:8000", "--quiet", "--format", "terminal"],
            )
        assert result.exit_code == 0


class TestQuietMode:
    def test_quiet_suppresses_output(self) -> None:
        runner = CliRunner()
        mock_result = _make_scan_result(1.0)

        with patch("agentgate.cli.asyncio.run", side_effect=_run_stub_factory(mock_result)):
            result = runner.invoke(
                cli,
                ["security-scan", "http://test:8000", "--quiet", "--format", "terminal"],
            )
        # In quiet mode with terminal format, no terminal output should be rendered
        assert "AgentGate" not in result.output


class TestCombinedScan:
    def test_source_submission_deploys_then_scans(self, tmp_path: Path) -> None:
        runner = CliRunner()
        (tmp_path / "Dockerfile").write_text("FROM python:3.11\n")
        (tmp_path / "main.py").write_text(
            'from fastapi import FastAPI\napp = FastAPI()\n@app.post("/search")\ndef search(query: str):\n    return {"ok": query}\n'
        )

        security_result = _make_scan_result(0.9)
        trust_result = _make_trust_result(TrustVerdict.ALLOW_CLEAN)
        captured: dict[str, object] = {}
        cleaned: list[str] = []
        deployment = RailwayExecutionResult(
            workspace_dir=tmp_path,
            project_id="proj-123",
            project_name="agentgate-scan-demo",
            environment_name="production",
            service_name="submission-agent",
            public_url="https://submission-agent.up.railway.app",
            dependency_services=[],
            issued_integrations=[],
            cleanup_project=False,
        )

        class _DummyScanner:
            def __init__(self, agent_config, scan_config, adapter=None, progress=None):
                captured["security_url"] = agent_config.url
                captured["security_request_field"] = agent_config.request_field
                captured["security_response_field"] = agent_config.response_field
                captured["security_request_defaults"] = agent_config.request_defaults

            async def run(self):
                return security_result

        class _DummyTrustScanner:
            def __init__(self, config, checks, progress=None):
                captured["trust_hosted_url"] = config.hosted_url
                captured["trust_service"] = config.railway_service

            async def run(self):
                return trust_result

        with (
            patch(
                "agentgate.cli.RailwayExecutor.deploy_submission",
                return_value=deployment,
            ),
            patch(
                "agentgate.cli.RailwayExecutor.cleanup",
                side_effect=lambda result: cleaned.append(result.public_url),
            ),
            patch(
                "agentgate.cli.Scanner",
                _DummyScanner,
            ),
            patch(
                "agentgate.cli.TrustScanner",
                _DummyTrustScanner,
            ),
            patch(
                "agentgate.cli.ReportEnricher.enrich",
                side_effect=lambda result: result,
            ),
            patch(
                "agentgate.cli._wait_for_review_target",
                return_value=None,
            ),
        ):
            result = runner.invoke(
                cli,
                [
                    "scan",
                    "--source-dir",
                    str(tmp_path),
                    "--format",
                    "json",
                    "--quiet",
                ],
            )

        assert result.exit_code == 0
        assert captured["security_url"] == "https://submission-agent.up.railway.app/search"
        assert captured["security_request_field"] == "query"
        assert captured["security_response_field"] == "results"
        assert captured["security_request_defaults"] == {"user_id": "agentgate-security-scan"}
        assert captured["trust_hosted_url"] == "https://submission-agent.up.railway.app"
        assert captured["trust_service"] == "submission-agent"
        assert cleaned == ["https://submission-agent.up.railway.app"]

    def test_source_submission_can_use_reusable_pool(self, tmp_path: Path) -> None:
        runner = CliRunner()
        pool_dir = tmp_path / "pool"
        pool_dir.mkdir()
        (tmp_path / "Dockerfile").write_text("FROM python:3.11\n")
        (tmp_path / "main.py").write_text(
            'from fastapi import FastAPI\napp = FastAPI()\n@app.post("/search")\ndef search(query: str):\n    return {"ok": query}\n'
        )

        security_result = _make_scan_result(0.9)
        trust_result = _make_trust_result(TrustVerdict.ALLOW_CLEAN)
        captured: dict[str, object] = {}
        deployment = RailwayExecutionResult(
            workspace_dir=pool_dir,
            project_id="proj-pool",
            project_name="agentgate-pool",
            environment_name="agentgate-pool",
            service_name="pooled-agent",
            public_url="https://pooled-agent.up.railway.app",
            dependency_services=["pgvector", "neo4j"],
            issued_integrations=[],
            cleanup_project=False,
            cleanup_workspace_dir=False,
            reused_pool=True,
        )

        def _deploy_submission(self, *, source_dir, dependencies, runtime_env, issued_integrations):
            captured["pool_workspace"] = str(self.pool_workspace_dir)
            captured["pool_environment"] = self.pool_environment
            captured["pool_service"] = self.pool_service_name
            return deployment

        class _DummyScanner:
            def __init__(self, agent_config, scan_config, adapter=None, progress=None):
                captured["security_url"] = agent_config.url

            async def run(self):
                return security_result

        class _DummyTrustScanner:
            def __init__(self, config, checks, progress=None):
                captured["trust_hosted_url"] = config.hosted_url

            async def run(self):
                return trust_result

        with (
            patch(
                "agentgate.cli.RailwayExecutor.deploy_submission",
                _deploy_submission,
            ),
            patch(
                "agentgate.cli.RailwayExecutor.cleanup",
                return_value=None,
            ),
            patch(
                "agentgate.cli.Scanner",
                _DummyScanner,
            ),
            patch(
                "agentgate.cli.TrustScanner",
                _DummyTrustScanner,
            ),
            patch(
                "agentgate.cli.ReportEnricher.enrich",
                side_effect=lambda result: result,
            ),
            patch(
                "agentgate.cli._wait_for_review_target",
                return_value=None,
            ),
        ):
            result = runner.invoke(
                cli,
                [
                    "scan",
                    "--source-dir",
                    str(tmp_path),
                    "--railway-pool-workspace",
                    str(pool_dir),
                    "--railway-pool-environment",
                    "agentgate-pool",
                    "--railway-pool-service",
                    "pooled-agent",
                    "--format",
                    "json",
                    "--quiet",
                ],
            )

        assert result.exit_code == 0
        assert captured["pool_workspace"] == str(pool_dir.resolve())
        assert captured["pool_environment"] == "agentgate-pool"
        assert captured["pool_service"] == "pooled-agent"
        assert captured["security_url"] == "https://pooled-agent.up.railway.app/search"
        assert captured["trust_hosted_url"] == "https://pooled-agent.up.railway.app"

    def test_combined_scan_requires_url_or_source_dir(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", "--format", "json", "--quiet"],
        )
        assert result.exit_code == 1


def test_railway_pool_init_warms_pool(tmp_path: Path) -> None:
    runner = CliRunner()
    result_payload = RailwayExecutionResult(
        workspace_dir=tmp_path,
        project_id="proj-pool",
        project_name="agentgate-pool",
        environment_name="agentgate-pool",
        service_name="submission-agent",
        public_url="https://submission-agent.up.railway.app",
        dependency_services=["pgvector", "neo4j", "redis"],
        cleanup_project=False,
        cleanup_workspace_dir=False,
        reused_pool=True,
        notes=["Reused a warm Railway pool instead of creating a fresh project."],
    )

    with patch(
        "agentgate.cli.RailwayExecutor.ensure_pool",
        return_value=result_payload,
    ):
        result = runner.invoke(
            cli,
            [
                "railway-pool-init",
                "--workspace",
                str(tmp_path),
                "--environment",
                "agentgate-pool",
                "--dependencies",
                "pgvector,neo4j,redis",
            ],
        )

    assert result.exit_code == 0
    assert "Reusable Railway pool is ready." in result.output
    assert "pgvector, neo4j, redis" in result.output
