from __future__ import annotations

from pathlib import Path

import pytest

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity, TrustVerdict
from agentgate.trust.runtime.railway_executor import RailwayExecutionResult
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

    assert result.scorecard.verdict == TrustVerdict.BLOCK
    assert result.scorecard.checks_run == 2
    assert result.scorecard.checks_failed == 1


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
    assert result.scorecard.verdict == TrustVerdict.BLOCK
    assert result.coverage is not None
    assert result.coverage.level == "none"


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

    def _deploy_submission(self, *, source_dir, dependencies, runtime_env, issued_integrations):
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

    def _deploy_submission(self, *, source_dir, dependencies, runtime_env, issued_integrations):
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
