from __future__ import annotations

from pathlib import Path

import pytest

from agentgate.trust.checks.static_code_signals import StaticCodeSignalsCheck
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustSeverity


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
