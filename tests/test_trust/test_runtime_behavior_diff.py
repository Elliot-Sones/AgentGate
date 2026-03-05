from __future__ import annotations

from pathlib import Path

import pytest

from agentgate.trust.checks.runtime_behavior_diff import RuntimeBehaviorDiffCheck
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


def _trace(profile: str = "review", **overrides) -> RuntimeTrace:
    defaults = dict(profile=profile, status="ok")
    defaults.update(overrides)
    return RuntimeTrace(**defaults)


@pytest.mark.asyncio
async def test_diff_single_profile_skipped(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.runtime_traces["review"] = _trace()
    check = RuntimeBehaviorDiffCheck()
    findings = await check.run(ctx)
    assert len(findings) == 1
    assert findings[0].passed is True
    assert findings[0].severity == TrustSeverity.INFO


@pytest.mark.asyncio
async def test_diff_no_deltas_passes(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.runtime_traces["review"] = _trace(
        network_destinations=["api.example.com"],
        tool_calls=["search"],
    )
    ctx.runtime_traces["prodlike"] = _trace(
        profile="prodlike",
        network_destinations=["api.example.com"],
        tool_calls=["search"],
    )
    check = RuntimeBehaviorDiffCheck()
    findings = await check.run(ctx)
    assert all(f.passed for f in findings)


@pytest.mark.asyncio
async def test_diff_extra_network_medium(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.runtime_traces["review"] = _trace(network_destinations=[])
    ctx.runtime_traces["prodlike"] = _trace(
        profile="prodlike",
        network_destinations=["evil.com"],
    )
    check = RuntimeBehaviorDiffCheck()
    findings = await check.run(ctx)
    failed = [f for f in findings if not f.passed]
    assert len(failed) >= 1
    assert any(f.severity == TrustSeverity.MEDIUM for f in failed)


@pytest.mark.asyncio
async def test_diff_extra_tools_high(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.runtime_traces["review"] = _trace(tool_calls=[])
    ctx.runtime_traces["prodlike"] = _trace(
        profile="prodlike",
        tool_calls=["shell_exec"],
    )
    check = RuntimeBehaviorDiffCheck()
    findings = await check.run(ctx)
    failed = [f for f in findings if not f.passed]
    assert len(failed) >= 1
    assert any(f.severity == TrustSeverity.HIGH for f in failed)


@pytest.mark.asyncio
async def test_diff_loopback_filtered(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.runtime_traces["review"] = _trace(network_destinations=[])
    ctx.runtime_traces["prodlike"] = _trace(
        profile="prodlike",
        network_destinations=["localhost", "127.0.0.1"],
    )
    check = RuntimeBehaviorDiffCheck()
    findings = await check.run(ctx)
    assert all(f.passed for f in findings)
