from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from agentgate.trust.checks.static_provenance import StaticProvenanceCheck
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustSeverity


def _config(tmp_path: Path, **overrides) -> TrustScanConfig:
    defaults = dict(
        source_dir=tmp_path,
        image_ref="example:latest@sha256:" + "a" * 64,
        manifest_path=None,
        output_dir=tmp_path / "out",
    )
    defaults.update(overrides)
    return TrustScanConfig(**defaults)


@pytest.mark.asyncio
async def test_provenance_fails_when_identity_constraints_missing(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.manifest = {"submission_id": "x"}

    check = StaticProvenanceCheck()
    with patch(
        "agentgate.trust.checks.static_provenance.shutil.which", return_value="/usr/bin/cosign"
    ):
        findings = await check.run(ctx)

    failed = [f for f in findings if not f.passed]
    assert failed
    assert any(f.severity == TrustSeverity.HIGH for f in failed)
    assert any("identity constraints" in f.title.lower() for f in failed)


@pytest.mark.asyncio
async def test_provenance_runs_cosign_with_pinned_identity(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.manifest = {
        "provenance": {
            "certificate_identity": "https://github.com/promptshop/listingpro/.github/workflows/release.yml@refs/heads/main",
            "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
        }
    }

    called_cmd: list[str] = []

    def _run_stub(cmd: list[str], **kwargs):
        nonlocal called_cmd
        called_cmd = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="verified", stderr="")

    check = StaticProvenanceCheck()
    with (
        patch(
            "agentgate.trust.checks.static_provenance.shutil.which", return_value="/usr/bin/cosign"
        ),
        patch(
            "agentgate.trust.checks.static_provenance.subprocess.run",
            side_effect=_run_stub,
        ),
    ):
        findings = await check.run(ctx)

    assert "--certificate-identity" in called_cmd
    assert "--certificate-oidc-issuer" in called_cmd
    assert called_cmd[0:2] == ["cosign", "verify"]
    assert all(f.passed for f in findings if f.severity == TrustSeverity.INFO)


@pytest.mark.asyncio
async def test_provenance_cosign_key_path_must_exist(tmp_path: Path) -> None:
    ctx = TrustScanContext(config=_config(tmp_path))
    ctx.manifest = {"provenance": {"cosign_key": "keys/missing.pub"}}

    check = StaticProvenanceCheck()
    with patch(
        "agentgate.trust.checks.static_provenance.shutil.which", return_value="/usr/bin/cosign"
    ):
        findings = await check.run(ctx)

    failed = [f for f in findings if not f.passed]
    assert failed
    assert any(f.severity == TrustSeverity.HIGH for f in failed)
    assert any("does not exist" in f.summary.lower() for f in failed)
