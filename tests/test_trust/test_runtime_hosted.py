from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from agentgate.trust.checks.runtime_hosted import HostedRuntimeCheck
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustSeverity
from agentgate.trust.runtime.trace_collector import RuntimeTrace
from agentgate.trust.runtime.adaptive.models import SpecialistReport


def _config(tmp_path: Path, **overrides) -> TrustScanConfig:
    defaults = dict(
        source_dir=tmp_path,
        image_ref="",
        manifest_path=None,
        output_dir=tmp_path / "out",
        hosted_url="https://agent.example.com",
    )
    defaults.update(overrides)
    return TrustScanConfig(**defaults)


@pytest.mark.asyncio
async def test_hosted_runtime_disabled_passes(tmp_path: Path) -> None:
    cfg = _config(tmp_path, collect_runtime_traces=False)
    ctx = TrustScanContext(config=cfg)

    findings = await HostedRuntimeCheck().run(ctx)

    assert len(findings) == 1
    assert findings[0].passed is True
    assert findings[0].severity == TrustSeverity.INFO


@pytest.mark.asyncio
async def test_hosted_runtime_requires_url(tmp_path: Path) -> None:
    cfg = _config(tmp_path, hosted_url="")
    ctx = TrustScanContext(config=cfg)

    findings = await HostedRuntimeCheck().run(ctx)

    failed = [f for f in findings if not f.passed]
    assert len(failed) == 1
    assert failed[0].severity == TrustSeverity.HIGH


@pytest.mark.asyncio
async def test_hosted_runtime_successful_run(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    ctx = TrustScanContext(config=cfg)
    (tmp_path / "out").mkdir(parents=True, exist_ok=True)

    mock_trace = RuntimeTrace(
        profile="hosted",
        status="ok",
        network_destinations=["api.example.com"],
        tool_calls=["search"],
    )

    with patch(
        "agentgate.trust.checks.runtime_hosted.HostedRuntimeRunner.run_profile",
        return_value=mock_trace,
    ):
        findings = await HostedRuntimeCheck().run(ctx)

    assert "hosted" in ctx.runtime_traces
    assert ctx.runtime_traces["hosted"].network_destinations == ["api.example.com"]
    assert any(f.passed for f in findings)


@pytest.mark.asyncio
async def test_hosted_runtime_blocks_invalid_dependency_manifest(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    cfg.dependency_validation_errors = ["Dependency service 'unknown' is not allowed."]
    ctx = TrustScanContext(config=cfg)

    findings = await HostedRuntimeCheck().run(ctx)

    assert len(findings) == 1
    assert findings[0].passed is False
    assert findings[0].severity == TrustSeverity.CRITICAL


@pytest.mark.asyncio
async def test_hosted_runtime_infers_dependencies_from_source(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "\n".join(
            [
                "import redis",
                'REDIS_URL = os.environ.get("REDIS_URL")',
            ]
        )
    )

    cfg = _config(tmp_path)
    ctx = TrustScanContext(config=cfg)
    (tmp_path / "out").mkdir(parents=True, exist_ok=True)

    mock_trace = RuntimeTrace(
        profile="hosted",
        status="ok",
        dependency_services=["redis"],
    )

    with patch(
        "agentgate.trust.checks.runtime_hosted.HostedRuntimeRunner.run_profile",
        return_value=mock_trace,
    ):
        findings = await HostedRuntimeCheck().run(ctx)

    assert any(f.passed for f in findings)
    assert ctx.config.dependencies[0].service == "redis"
    assert ctx.config.runtime_env == {"REDIS_URL": "redis://redis:6379/0"}


@pytest.mark.asyncio
async def test_hosted_runtime_uses_hosted_runner(tmp_path: Path) -> None:
    cfg = _config(
        tmp_path,
        hosted_url="https://agent.example.com",
        railway_workspace_dir=tmp_path,
        railway_service="demo-agent",
        railway_environment="production",
    )
    ctx = TrustScanContext(config=cfg)
    (tmp_path / "out").mkdir(parents=True, exist_ok=True)

    mock_trace = RuntimeTrace(
        profile="hosted",
        status="ok",
        dependency_services=["postgres"],
        probe_responses=[
            {
                "method": "GET",
                "path": "/",
                "status_code": 200,
                "body_snippet": "",
                "error": "",
            }
        ],
    )

    class _DummyHostedRunner:
        def __init__(self, *args, **kwargs):
            self.runtime_context = {"railway_service": "demo-agent"}

        def run_profile(self, profile, canary_profile, artifact_dir):
            return mock_trace

    with patch(
        "agentgate.trust.checks.runtime_hosted.HostedRuntimeRunner",
        _DummyHostedRunner,
    ):
        findings = await HostedRuntimeCheck().run(ctx)

    assert ctx.runtime_traces["hosted"].status == "ok"
    assert ctx.hosted_runtime_context == {"railway_service": "demo-agent"}
    assert any(f.passed for f in findings)


@pytest.mark.asyncio
async def test_hosted_runtime_surfaces_specialist_findings(tmp_path: Path) -> None:
    cfg = _config(tmp_path, hosted_url="https://agent.example.com")
    cfg.adaptive_trust = True
    cfg.anthropic_api_key = "sk-test"
    ctx = TrustScanContext(config=cfg)
    (tmp_path / "out").mkdir(parents=True, exist_ok=True)

    mock_trace = RuntimeTrace(profile="hosted", status="ok")

    class _DummyHostedRunner:
        def __init__(self, *args, **kwargs):
            self.runtime_context = {"probing_mode": "adaptive"}
            self.probing_mode = "adaptive"
            self.adaptive_fallback_reason = ""
            self.specialist_reports = [
                SpecialistReport(
                    specialist="egress_prober",
                    probes_sent=2,
                    probes_succeeded=1,
                    findings=["Undeclared external fetch behavior detected"],
                    evidence=["Response referenced attacker.example"],
                    severity="high",
                )
            ]

        def run_profile(self, profile, canary_profile, artifact_dir):
            return mock_trace

    with patch(
        "agentgate.trust.checks.runtime_hosted.HostedRuntimeRunner",
        _DummyHostedRunner,
    ):
        findings = await HostedRuntimeCheck().run(ctx)

    specialist_findings = [f for f in findings if f.title.startswith("Adaptive specialist flagged")]
    assert len(specialist_findings) == 1
    assert specialist_findings[0].passed is False
    assert specialist_findings[0].severity == TrustSeverity.HIGH
