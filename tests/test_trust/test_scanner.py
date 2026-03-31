from __future__ import annotations

from pathlib import Path

import pytest

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.checks.static_code_signals import StaticCodeSignalsCheck
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity, TrustVerdict
from agentgate.trust.runtime.railway_executor import RailwayExecutionError, RailwayExecutionResult
from agentgate.trust.models import CoverageSummary
from agentgate.trust.scanner import TrustScanner


class PassingCheck(BaseTrustCheck):
    check_id = "passing_check"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        return [
            self.finding(
                title="pass",
                category=TrustCategory.DECLARATION,
                severity=TrustSeverity.INFO,
                passed=True,
                summary="ok",
            )
        ]


class CriticalCheck(BaseTrustCheck):
    check_id = "critical_check"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        return [
            self.finding(
                title="critical",
                category=TrustCategory.CANARY,
                severity=TrustSeverity.CRITICAL,
                passed=False,
                summary="bad",
            )
        ]


class HostedTraceCheck(BaseTrustCheck):
    check_id = "hosted_trace_check"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        from agentgate.trust.runtime.trace_collector import RuntimeTrace

        ctx.runtime_traces["hosted"] = RuntimeTrace(
            profile="hosted",
            status="ok",
            inspect_network_mode="hosted",
        )
        return [
            self.finding(
                title="hosted",
                category=TrustCategory.RUNTIME_INTEGRITY,
                severity=TrustSeverity.INFO,
                passed=True,
                summary="hosted trace",
            )
        ]


class RuntimeShouldNotRunCheck(BaseTrustCheck):
    check_id = "runtime_should_not_run"

    def __init__(self) -> None:
        self.called = False

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        self.called = True
        return [
            self.finding(
                title="runtime",
                category=TrustCategory.RUNTIME_INTEGRITY,
                severity=TrustSeverity.INFO,
                passed=True,
                summary="runtime ok",
            )
        ]


def _write_normalizer_fixture(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["python", "app.py"]\n'
    )
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_security.py").write_text("exec(user_input)\n")


class LegacyFindingCheck(BaseTrustCheck):
    check_id = "legacy_check"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        return [
            self.finding(
                title="legacy",
                category=TrustCategory.HIDDEN_BEHAVIOR,
                severity=TrustSeverity.HIGH,
                passed=False,
                summary="legacy finding",
            )
        ]


@pytest.mark.asyncio
async def test_trust_scanner_computes_block_verdict(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text('FROM python:3.11\nCMD ["python", "app.py"]\n')
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="example:latest",
        manifest_path=None,
        output_dir=tmp_path / "out",
        hosted_url="https://agent.example.com",
    )
    scanner = TrustScanner(config=config, checks=[PassingCheck(), CriticalCheck()])

    result = await scanner.run()

    assert result.scorecard.verdict == TrustVerdict.MANUAL_REVIEW
    assert result.scorecard.checks_run == 2
    assert result.scorecard.checks_failed == 1


@pytest.mark.asyncio
async def test_trust_scanner_builds_context_for_normalized_checks(tmp_path: Path) -> None:
    _write_normalizer_fixture(tmp_path)
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="",
        manifest_path=None,
        output_dir=tmp_path / "out",
        hosted_url="https://agent.example.com",
    )
    scanner = TrustScanner(config=config, checks=[StaticCodeSignalsCheck()])

    result = await scanner.run()

    finding = next(f for f in result.findings if f.check_id == "static_code_signals")
    assert finding.legacy_interpretation is False
    assert finding.context.file_class == "test"
    assert finding.context.reachability == "not_reached"
    assert finding.severity == TrustSeverity.INFO


@pytest.mark.asyncio
async def test_trust_scanner_tags_legacy_findings(tmp_path: Path) -> None:
    _write_normalizer_fixture(tmp_path)
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="",
        manifest_path=None,
        output_dir=tmp_path / "out",
        hosted_url="https://agent.example.com",
    )
    scanner = TrustScanner(config=config, checks=[LegacyFindingCheck()])

    result = await scanner.run()

    finding = result.findings[0]
    assert finding.legacy_interpretation is True
    assert finding.base_severity == TrustSeverity.HIGH
    assert getattr(finding, "context", None) is None


@pytest.mark.asyncio
async def test_trust_scanner_builds_hosted_runtime_profile(tmp_path: Path) -> None:
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="",
        manifest_path=None,
        output_dir=tmp_path / "out",
        hosted_url="https://agent.example.com",
    )
    scanner = TrustScanner(config=config, checks=[HostedTraceCheck()])

    result = await scanner.run()

    assert result.runtime_profiles[0].name == "hosted"


@pytest.mark.asyncio
async def test_trust_scanner_fails_fast_for_unsupported_source_submission(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="",
        manifest_path=None,
        output_dir=tmp_path / "out",
    )
    scanner = TrustScanner(config=config, checks=[PassingCheck()])

    result = await scanner.run()

    assert result.submission_support is not None
    assert result.submission_support.supported is False
    assert result.submission_support.reason == "dockerfile_missing"
    assert result.scorecard.verdict == TrustVerdict.MANUAL_REVIEW
    assert result.coverage is not None
    assert result.coverage.level == "limited"
    assert result.coverage.coverage_recommendation == "manual_review"


@pytest.mark.asyncio
async def test_trust_scanner_deploys_source_submission_when_no_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["python", "app.py"]\n'
    )
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="",
        manifest_path=None,
        output_dir=tmp_path / "out",
    )

    deployed_urls: list[str] = []

    def _deploy_submission(
        self,
        *,
        source_dir,
        dockerfile_path,
        dependencies,
        runtime_env,
        issued_integrations,
    ):
        return RailwayExecutionResult(
            workspace_dir=tmp_path,
            project_id="proj-123",
            project_name="agentgate-scan-demo",
            environment_name="production",
            service_name="submission-agent",
            public_url="https://submission-agent.up.railway.app",
            dependency_services=[dependency.service for dependency in dependencies],
            issued_integrations=list(issued_integrations),
            cleanup_project=False,
        )

    def _cleanup(self, result):
        deployed_urls.append(result.public_url)

    class _AssertsDeploymentCheck(BaseTrustCheck):
        check_id = "asserts_deployment"

        async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
            from agentgate.trust.runtime.trace_collector import RuntimeTrace

            assert ctx.config.hosted_url == "https://submission-agent.up.railway.app"
            ctx.runtime_traces["hosted"] = RuntimeTrace(
                profile="hosted",
                status="ok",
                probe_responses=[{"path": "/", "status_code": 200}],
            )
            return [
                self.finding(
                    title="deployed",
                    category=TrustCategory.RUNTIME_INTEGRITY,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary="deployment ok",
                )
            ]

    monkeypatch.setattr(
        "agentgate.trust.scanner.RailwayExecutor.deploy_submission",
        _deploy_submission,
    )
    monkeypatch.setattr(
        "agentgate.trust.scanner.RailwayExecutor.cleanup",
        _cleanup,
    )

    scanner = TrustScanner(config=config, checks=[_AssertsDeploymentCheck()])
    result = await scanner.run()

    assert result.deployment_summary is not None
    assert result.deployment_summary.public_url == "https://submission-agent.up.railway.app"
    assert result.generated_runtime_profile is not None
    assert result.generated_runtime_profile.http_supported is True
    assert result.coverage is not None
    assert result.coverage.level == "partial"
    assert deployed_urls == ["https://submission-agent.up.railway.app"]


@pytest.mark.asyncio
async def test_trust_scanner_passes_inferred_port_to_deployment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8501\nCMD ["uvicorn", "app:app", "--port", "8501"]\n'
    )
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="",
        manifest_path=None,
        output_dir=tmp_path / "out",
    )

    captured: dict[str, object] = {}

    def _deploy_submission(
        self,
        *,
        source_dir,
        dockerfile_path,
        dependencies,
        runtime_env,
        issued_integrations,
    ):
        captured["runtime_env"] = dict(runtime_env)
        return RailwayExecutionResult(
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

    monkeypatch.setattr(
        "agentgate.trust.scanner.RailwayExecutor.deploy_submission",
        _deploy_submission,
    )
    monkeypatch.setattr(
        "agentgate.trust.scanner.RailwayExecutor.cleanup",
        lambda self, result: None,
    )

    scanner = TrustScanner(config=config, checks=[])
    await scanner.run()

    assert captured["runtime_env"] == {"PORT": "8501"}


@pytest.mark.asyncio
async def test_trust_scanner_can_deploy_into_reusable_pool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool_dir = tmp_path / "pool"
    pool_dir.mkdir()
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["python", "app.py"]\n'
    )
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="",
        manifest_path=None,
        output_dir=tmp_path / "out",
        railway_pool_workspace_dir=pool_dir,
        railway_pool_environment="agentgate-pool",
        railway_pool_service="pooled-agent",
    )

    captured: dict[str, object] = {}

    def _deploy_submission(
        self,
        *,
        source_dir,
        dockerfile_path,
        dependencies,
        runtime_env,
        issued_integrations,
    ):
        captured["pool_workspace"] = str(self.pool_workspace_dir)
        captured["pool_environment"] = self.pool_environment
        captured["pool_service"] = self.pool_service_name
        return RailwayExecutionResult(
            workspace_dir=pool_dir,
            project_id="proj-pool",
            project_name="agentgate-pool",
            environment_name="agentgate-pool",
            service_name="pooled-agent",
            public_url="https://pooled-agent.up.railway.app",
            dependency_services=[],
            issued_integrations=list(issued_integrations),
            cleanup_project=False,
            cleanup_workspace_dir=False,
            reused_pool=True,
            notes=["Reused a warm Railway pool instead of creating a fresh project."],
        )

    class _AssertsDeploymentCheck(BaseTrustCheck):
        check_id = "asserts_pool_deployment"

        async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
            assert ctx.config.hosted_url == "https://pooled-agent.up.railway.app"
            return [
                self.finding(
                    title="deployed",
                    category=TrustCategory.RUNTIME_INTEGRITY,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary="deployment ok",
                )
            ]

    monkeypatch.setattr(
        "agentgate.trust.scanner.RailwayExecutor.deploy_submission",
        _deploy_submission,
    )
    monkeypatch.setattr(
        "agentgate.trust.scanner.RailwayExecutor.cleanup",
        lambda self, result: None,
    )

    result = await TrustScanner(config=config, checks=[_AssertsDeploymentCheck()]).run()

    assert result.deployment_summary is not None
    assert result.deployment_summary.public_url == "https://pooled-agent.up.railway.app"
    assert any("warm Railway pool" in note for note in (result.deployment_summary.notes or []))
    assert captured["pool_workspace"] == str(pool_dir.resolve())
    assert captured["pool_environment"] == "agentgate-pool"
    assert captured["pool_service"] == "pooled-agent"


@pytest.mark.asyncio
async def test_trust_scanner_keeps_static_checks_when_deployment_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["python", "app.py"]\n'
    )
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="",
        manifest_path=None,
        output_dir=tmp_path / "out",
    )
    runtime_check = RuntimeShouldNotRunCheck()

    def _deploy_submission(
        self,
        *,
        source_dir,
        dockerfile_path,
        dependencies,
        runtime_env,
        issued_integrations,
    ):
        raise RailwayExecutionError("railway deploy failed")

    monkeypatch.setattr(
        "agentgate.trust.scanner.RailwayExecutor.deploy_submission",
        _deploy_submission,
    )

    result = await TrustScanner(config=config, checks=[PassingCheck(), runtime_check]).run()

    assert runtime_check.called is False
    assert result.scorecard.checks_run == 1
    assert result.scorecard.checks_passed == 1
    assert result.scorecard.checks_failed == 0
    assert result.scorecard.verdict == TrustVerdict.MANUAL_REVIEW
    assert result.metadata["deployment_error"] == "railway deploy failed"
    assert any(finding.check_id == "deployment" for finding in result.findings)
    skipped = next(
        finding for finding in result.findings if finding.check_id == "runtime_checks_skipped"
    )
    assert "runtime_should_not_run" in skipped.summary


class TestPriorFindings:
    def test_prior_findings_filters_to_failed_only(self) -> None:
        from agentgate.trust.scanner import TrustScanner

        findings = [
            TrustFinding(
                check_id="static_code_signals",
                title="exec() call detected",
                category=TrustCategory.HIDDEN_BEHAVIOR,
                severity=TrustSeverity.HIGH,
                passed=False,
                summary="exec() at agent.py:45",
                location_path="agent.py",
                location_line=45,
            ),
            TrustFinding(
                check_id="static_manifest",
                title="Manifest parsed successfully",
                category=TrustCategory.DECLARATION,
                severity=TrustSeverity.INFO,
                passed=True,
                summary="Trust manifest is present.",
            ),
        ]
        summaries = TrustScanner._summarize_prior_findings(findings)
        assert len(summaries) == 1
        assert "[HIGH]" in summaries[0]
        assert "exec() call detected" in summaries[0]

    def test_prior_findings_caps_at_20(self) -> None:
        from agentgate.trust.scanner import TrustScanner

        findings = [
            TrustFinding(
                check_id=f"check_{i}",
                title=f"Finding {i}",
                category=TrustCategory.HIDDEN_BEHAVIOR,
                severity=TrustSeverity.LOW,
                passed=False,
                summary=f"Issue {i}",
            )
            for i in range(30)
        ]
        summaries = TrustScanner._summarize_prior_findings(findings)
        assert len(summaries) == 20

    def test_prior_findings_ordered_by_severity(self) -> None:
        from agentgate.trust.scanner import TrustScanner

        findings = [
            TrustFinding(
                check_id="low",
                title="Low issue",
                category=TrustCategory.HIDDEN_BEHAVIOR,
                severity=TrustSeverity.LOW,
                passed=False,
                summary="Low",
            ),
            TrustFinding(
                check_id="critical",
                title="Critical issue",
                category=TrustCategory.HIDDEN_BEHAVIOR,
                severity=TrustSeverity.CRITICAL,
                passed=False,
                summary="Critical",
            ),
        ]
        summaries = TrustScanner._summarize_prior_findings(findings)
        assert summaries[0].startswith("[CRITICAL]")
        assert summaries[1].startswith("[LOW]")


def test_confidence_summary_does_not_credit_failed_adaptive_probe(tmp_path: Path) -> None:
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="",
        manifest_path=None,
        output_dir=tmp_path / "out",
        hosted_url="https://agent.example.com",
    )
    ctx = TrustScanContext(config=config)
    ctx.hosted_runtime_context = {
        "probing_mode": "static",
        "adaptive_fallback_reason": "llm unavailable",
    }

    coverage = CoverageSummary(level="partial")
    confidence = TrustScanner._build_confidence_summary(ctx, coverage, "")

    assert confidence.score < 100
    assert any("fell back to static hosted probes" in driver for driver in confidence.drivers)
