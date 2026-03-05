from __future__ import annotations

from pathlib import Path

import pytest

from agentscorer.trust.checks.runtime_canary import RuntimeCanaryCheck
from agentscorer.trust.config import TrustScanConfig
from agentscorer.trust.context import TrustScanContext
from agentscorer.trust.models import TrustSeverity
from agentscorer.trust.runtime.trace_collector import RuntimeTrace


def _config(tmp_path: Path, **overrides) -> TrustScanConfig:
    defaults = dict(
        source_dir=tmp_path,
        image_ref="test:latest",
        manifest_path=None,
        output_dir=tmp_path / "out",
    )
    defaults.update(overrides)
    return TrustScanConfig(**defaults)


def _trace(profile: str = "review", **overrides) -> RuntimeTrace:
    defaults = dict(profile=profile, status="ok")
    defaults.update(overrides)
    return RuntimeTrace(**defaults)


@pytest.mark.asyncio
async def test_canary_no_traces_fails(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    check = RuntimeCanaryCheck()
    findings = await check.run(ctx)
    assert len(findings) == 1
    assert findings[0].passed is False
    assert findings[0].severity == TrustSeverity.MEDIUM


@pytest.mark.asyncio
async def test_canary_clean_trace_passes(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.runtime_traces["review"] = _trace(logs="all clear, nothing suspicious")
    check = RuntimeCanaryCheck()
    findings = await check.run(ctx)
    assert all(f.passed for f in findings)


@pytest.mark.asyncio
async def test_canary_hit_detected_critical(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.runtime_traces["review"] = _trace(
        canary_hits=["PROMPTSHOP_FAKE_API_KEY"],
        logs="safe output",
    )
    check = RuntimeCanaryCheck()
    findings = await check.run(ctx)
    failed = [f for f in findings if not f.passed]
    assert len(failed) >= 1
    assert failed[0].severity == TrustSeverity.CRITICAL


@pytest.mark.asyncio
async def test_canary_detects_from_logs_too(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.runtime_traces["review"] = _trace(
        logs="found ps_live_canary_8f9d2b1c in output",
    )
    check = RuntimeCanaryCheck()
    findings = await check.run(ctx)
    failed = [f for f in findings if not f.passed]
    assert len(failed) >= 1
    assert failed[0].severity == TrustSeverity.CRITICAL
