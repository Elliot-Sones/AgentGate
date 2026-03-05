from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from agentgate.trust.checks.runtime_sandbox import RuntimeSandboxCheck
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustSeverity
from agentgate.trust.runtime.trace_collector import RuntimeTrace


def _config(tmp_path: Path, **overrides) -> TrustScanConfig:
    defaults = dict(
        source_dir=tmp_path,
        image_ref="test:latest",
        manifest_path=None,
        output_dir=tmp_path / "out",
    )
    defaults.update(overrides)
    return TrustScanConfig(**defaults)


@pytest.mark.asyncio
async def test_sandbox_disabled_passes(tmp_path: Path) -> None:
    cfg = _config(tmp_path, collect_runtime_traces=False)
    ctx = TrustScanContext(config=cfg)
    check = RuntimeSandboxCheck()
    findings = await check.run(ctx)
    assert len(findings) == 1
    assert findings[0].passed is True
    assert findings[0].severity == TrustSeverity.INFO


@pytest.mark.asyncio
async def test_sandbox_image_inspect_fails(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    ctx = TrustScanContext(config=cfg)
    check = RuntimeSandboxCheck()
    with patch(
        "agentgate.trust.checks.runtime_sandbox.DockerRunner.inspect_image",
        return_value=(False, "image not found"),
    ):
        findings = await check.run(ctx)
    failed = [f for f in findings if not f.passed]
    assert len(failed) >= 1
    assert failed[0].severity == TrustSeverity.HIGH


@pytest.mark.asyncio
async def test_sandbox_successful_run(tmp_path: Path) -> None:
    cfg = _config(tmp_path, profile="review")
    ctx = TrustScanContext(config=cfg)
    (tmp_path / "out").mkdir(parents=True, exist_ok=True)

    mock_trace = RuntimeTrace(
        profile="review",
        status="ok",
        network_destinations=["api.example.com"],
        tool_calls=["search"],
    )

    check = RuntimeSandboxCheck()
    with patch(
        "agentgate.trust.checks.runtime_sandbox.DockerRunner.inspect_image",
        return_value=(True, ""),
    ), patch(
        "agentgate.trust.checks.runtime_sandbox.DockerRunner.run_profile",
        return_value=mock_trace,
    ):
        findings = await check.run(ctx)

    assert "review" in ctx.runtime_traces
    assert ctx.runtime_traces["review"].network_destinations == ["api.example.com"]
    assert any(f.passed for f in findings)
