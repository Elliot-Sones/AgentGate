from __future__ import annotations

from pathlib import Path

import pytest

from agentgate.trust.checks.runtime_egress import RuntimeEgressCheck
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
async def test_egress_no_traces_fails(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    check = RuntimeEgressCheck()
    findings = await check.run(ctx)
    assert len(findings) == 1
    assert findings[0].passed is False
    assert findings[0].severity == TrustSeverity.MEDIUM


@pytest.mark.asyncio
async def test_egress_clean_declared_domains(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.manifest = {"declared_external_domains": ["example.com"]}
    ctx.runtime_traces["review"] = _trace(network_destinations=["example.com"])
    check = RuntimeEgressCheck()
    findings = await check.run(ctx)
    assert all(f.passed for f in findings)


@pytest.mark.asyncio
async def test_egress_undeclared_destination_critical(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.manifest = {"declared_external_domains": ["example.com"]}
    ctx.runtime_traces["review"] = _trace(network_destinations=["evil.com"])
    check = RuntimeEgressCheck()
    findings = await check.run(ctx)
    failed = [f for f in findings if not f.passed]
    assert len(failed) >= 1
    assert failed[0].severity == TrustSeverity.CRITICAL
    assert getattr(failed[0], "context", None) is not None
    assert failed[0].context.destination_class == "unknown_external"


@pytest.mark.asyncio
async def test_egress_localhost_ignored(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.manifest = {"declared_external_domains": []}
    ctx.runtime_traces["review"] = _trace(network_destinations=["localhost", "127.0.0.1", "::1"])
    check = RuntimeEgressCheck()
    findings = await check.run(ctx)
    assert all(f.passed for f in findings)


@pytest.mark.asyncio
async def test_egress_subdomain_matching(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.manifest = {"declared_external_domains": ["example.com"]}
    ctx.runtime_traces["review"] = _trace(network_destinations=["sub.example.com"])
    check = RuntimeEgressCheck()
    findings = await check.run(ctx)
    assert all(f.passed for f in findings)


@pytest.mark.asyncio
async def test_egress_allowlist_overrides(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    cfg.egress_allowlist = {"override.com"}
    ctx = TrustScanContext(config=cfg)
    ctx.manifest = {"declared_external_domains": []}
    ctx.runtime_traces["review"] = _trace(network_destinations=["override.com"])
    check = RuntimeEgressCheck()
    findings = await check.run(ctx)
    assert all(f.passed for f in findings)


@pytest.mark.asyncio
async def test_egress_log_only_signal_triggers_manual_review_finding(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.manifest = {"declared_external_domains": ["example.com"]}
    ctx.runtime_traces["review"] = _trace(
        network_destinations=["example.com"],
        network_destinations_procfs=[],
        inspect_network_mode="bridge",
    )
    check = RuntimeEgressCheck()
    findings = await check.run(ctx)
    failed = [f for f in findings if not f.passed]
    assert len(failed) == 1
    assert failed[0].severity == TrustSeverity.MEDIUM


@pytest.mark.asyncio
async def test_egress_allows_procfs_ip_when_declared_domain_resolves(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.manifest = {"declared_external_domains": ["example.com"]}
    ctx.runtime_traces["review"] = _trace(
        network_destinations=["example.com", "93.184.216.34"],
        network_destinations_logs=["example.com"],
        network_destinations_procfs=["93.184.216.34"],
        inspect_network_mode="bridge",
    )

    from agentgate.trust.checks import runtime_egress as re_mod

    re_mod._resolve_domain_ips.cache_clear()
    original = re_mod._resolve_domain_ips

    def _stub(domain: str):
        if domain == "example.com":
            return {"93.184.216.34"}
        return set()

    re_mod._resolve_domain_ips = _stub  # type: ignore[assignment]
    try:
        findings = await RuntimeEgressCheck().run(ctx)
    finally:
        re_mod._resolve_domain_ips = original  # type: ignore[assignment]

    assert all(f.passed for f in findings)


@pytest.mark.asyncio
async def test_egress_verified_internal_destination_is_allowed(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.runtime_traces["review"] = _trace(
        network_destinations=["10.165.167.93"],
        internal_network_destinations=["10.165.167.93"],
    )

    findings = await RuntimeEgressCheck().run(ctx)

    assert any(f.passed for f in findings)
    assert all(f.severity != TrustSeverity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_egress_private_destination_without_verification_is_flagged(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.runtime_traces["review"] = _trace(network_destinations=["10.0.0.55"])

    findings = await RuntimeEgressCheck().run(ctx)

    failed = [f for f in findings if not f.passed]
    assert len(failed) == 1
    assert failed[0].severity == TrustSeverity.MEDIUM
    assert "Private network destination" in failed[0].title
    assert getattr(failed[0], "context", None) is not None
    assert failed[0].context.destination_class == "private_unattributed"


@pytest.mark.asyncio
async def test_egress_telemetry_registry_allows_framework_calls(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.hosted_runtime_context = {"telemetry_packages": ["streamlit"]}
    ctx.runtime_traces["review"] = _trace(network_destinations=["browser.gatherusagestats"])

    findings = await RuntimeEgressCheck().run(ctx)

    assert all(f.passed for f in findings)
