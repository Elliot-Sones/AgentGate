from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from agentgate.cli import cli
from agentgate.trust.config import DependencySpec
from agentgate.trust.models import (
    TrustCategory,
    TrustFinding,
    TrustScanResult,
    TrustScorecard,
    TrustSeverity,
    TrustVerdict,
)
from agentgate.trust.runtime.railway_discovery import RailwayDiscoveryResult


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
                "--url",
                "https://agent.example.com",
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
                "--url",
                "https://agent.example.com",
                "--format",
                "terminal",
                "--quiet",
                "--fail-on",
                "block",
            ],
        )
    assert result.exit_code == 0

def test_trust_scan_accepts_promptshop_report_profile() -> None:
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
                "--url",
                "https://agent.example.com",
                "--format",
                "json",
                "--quiet",
                "--report-profile",
                "promptshop",
            ],
        )
    assert result.exit_code == 0


def test_railway_manifest_command_writes_sanitized_file(tmp_path) -> None:
    runner = CliRunner()
    output_path = tmp_path / "trust_manifest.railway.yaml"
    discovery = RailwayDiscoveryResult(
        workspace_dir=tmp_path,
        project_name="mem0-agentgate-demo",
        project_id="proj-123",
        environment_name="production",
        service_name="mem0-agentgate-demo",
        public_domain="mem0-agentgate-demo-production.up.railway.app",
        dependencies=[DependencySpec(service="neo4j")],
        runtime_env={"NEO4J_URI": "bolt://neo4j:7687"},
        notes=["Discovered Railway service graph."],
        omitted_sensitive_env=["OPENAI_API_KEY"],
    )

    with patch("agentgate.cli.discover_railway_runtime", return_value=discovery):
        result = runner.invoke(
            cli,
            [
                "railway-manifest",
                "--workspace",
                str(tmp_path),
                "--output",
                str(output_path),
            ],
        )

    assert result.exit_code == 0
    text = output_path.read_text()
    assert "service: neo4j" in text
    assert "platform: railway" in text
    assert "OPENAI_API_KEY" in text


def test_trust_scan_can_generate_railway_manifest(tmp_path) -> None:
    runner = CliRunner()
    captured = {}
    discovery = RailwayDiscoveryResult(
        workspace_dir=tmp_path,
        project_name="mem0-agentgate-demo",
        project_id="proj-123",
        environment_name="production",
        service_name="mem0-agentgate-demo",
        dependencies=[DependencySpec(service="postgres")],
        runtime_env={"POSTGRES_HOST": "postgres"},
        notes=["Discovered Railway service graph."],
    )
    mock_result = _make_result(TrustVerdict.ALLOW_CLEAN)

    class _DummyScanner:
        def __init__(self, config, checks, progress):
            captured["config"] = config

        async def run(self):
            return mock_result

    with patch("agentgate.cli.discover_railway_runtime", return_value=discovery), patch(
        "agentgate.cli.TrustScanner",
        _DummyScanner,
    ):
        result = runner.invoke(
            cli,
            [
                "trust-scan",
                "--url",
                "https://agent.example.com",
                "--source-dir",
                str(tmp_path),
                "--railway-discover",
                "--format",
                "json",
                "--quiet",
            ],
        )

    assert result.exit_code == 0
    manifest_path = captured["config"].manifest_path
    assert manifest_path is not None
    assert manifest_path.name == "railway_discovered_manifest.yaml"
    assert manifest_path.exists()
    assert "POSTGRES_HOST: postgres" in manifest_path.read_text()


def test_trust_scan_railway_discovery_skips_source_refinement_without_markers(tmp_path) -> None:
    runner = CliRunner()
    mock_result = _make_result(TrustVerdict.ALLOW_CLEAN)
    captured = {}
    discovery = RailwayDiscoveryResult(
        workspace_dir=tmp_path,
        project_name="mem0-agentgate-demo",
        project_id="proj-123",
        environment_name="production",
        service_name="mem0-agentgate-demo",
    )

    def _discover(**kwargs):
        captured.update(kwargs)
        return discovery

    class _DummyScanner:
        def __init__(self, config, checks, progress):
            self.config = config

        async def run(self):
            return mock_result

    with patch("agentgate.cli.discover_railway_runtime", side_effect=_discover), patch(
        "agentgate.cli.TrustScanner",
        _DummyScanner,
    ):
        result = runner.invoke(
            cli,
            [
                "trust-scan",
                "--url",
                "https://agent.example.com",
                "--source-dir",
                str(tmp_path),
                "--railway-discover",
                "--format",
                "json",
                "--quiet",
            ],
        )

    assert result.exit_code == 0
    assert captured["source_dir"] is None


def test_trust_scan_accepts_hosted_url_without_image(tmp_path) -> None:
    runner = CliRunner()
    captured = {}
    mock_result = _make_result(TrustVerdict.ALLOW_CLEAN)

    class _DummyScanner:
        def __init__(self, config, checks, progress):
            captured["config"] = config

        async def run(self):
            return mock_result

    with patch("agentgate.cli.TrustScanner", _DummyScanner):
        result = runner.invoke(
            cli,
            [
                "trust-scan",
                "--url",
                "https://agent.example.com",
                "--format",
                "json",
                "--quiet",
            ],
        )

    assert result.exit_code == 0
    assert captured["config"].hosted_url == "https://agent.example.com"


def test_trust_scan_accepts_source_submission_without_url(tmp_path) -> None:
    runner = CliRunner()
    captured = {}
    mock_result = _make_result(TrustVerdict.ALLOW_CLEAN)

    (tmp_path / "Dockerfile").write_text("FROM python:3.11\n")

    class _DummyScanner:
        def __init__(self, config, checks, progress):
            captured["config"] = config

        async def run(self):
            return mock_result

    with patch("agentgate.cli.TrustScanner", _DummyScanner):
        result = runner.invoke(
            cli,
            [
                "trust-scan",
                "--source-dir",
                str(tmp_path),
                "--format",
                "json",
                "--quiet",
                "--strict-production-contract",
            ],
        )

    assert result.exit_code == 0
    assert captured["config"].hosted_url == ""
    assert captured["config"].strict_production_contract is True


def test_trust_scan_requires_url_or_source_dir() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "trust-scan",
            "--quiet",
        ],
    )
    assert result.exit_code == 1
