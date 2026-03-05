from __future__ import annotations

from pathlib import Path

import pytest

from agentscorer.trust.checks.runtime_tool_audit import RuntimeToolAuditCheck
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
async def test_tool_audit_no_traces_fails(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    check = RuntimeToolAuditCheck()
    findings = await check.run(ctx)
    assert len(findings) == 1
    assert findings[0].passed is False
    assert findings[0].severity == TrustSeverity.MEDIUM


@pytest.mark.asyncio
async def test_tool_audit_no_markers_fails_for_missing_telemetry(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.runtime_traces["review"] = _trace(tool_calls=[])
    check = RuntimeToolAuditCheck()
    findings = await check.run(ctx)
    assert len(findings) == 1
    assert findings[0].passed is False
    assert findings[0].severity == TrustSeverity.MEDIUM


@pytest.mark.asyncio
async def test_tool_audit_declared_tools_pass(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.manifest = {"declared_tools": ["search", "calculator"]}
    ctx.runtime_traces["review"] = _trace(tool_calls=["search", "calculator"])
    check = RuntimeToolAuditCheck()
    findings = await check.run(ctx)
    assert all(f.passed for f in findings)


@pytest.mark.asyncio
async def test_tool_audit_undeclared_tool_fails(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.manifest = {"declared_tools": ["search"]}
    ctx.runtime_traces["review"] = _trace(tool_calls=["search", "shell_exec"])
    check = RuntimeToolAuditCheck()
    findings = await check.run(ctx)
    failed = [f for f in findings if not f.passed]
    assert len(failed) >= 1
    assert failed[0].severity == TrustSeverity.HIGH


@pytest.mark.asyncio
async def test_tool_audit_uses_process_events_as_fallback_signal(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.manifest = {"declared_tools": ["curl"]}
    ctx.runtime_traces["review"] = _trace(
        tool_calls=[],
        process_events=["EXEC:/usr/bin/curl https://example.com"],
    )
    check = RuntimeToolAuditCheck()
    findings = await check.run(ctx)
    assert all(f.passed for f in findings)
