from __future__ import annotations

from pathlib import Path

import pytest

from agentgate.trust.checks.static_manifest import StaticManifestCheck
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext


@pytest.mark.asyncio
async def test_manifest_missing_reports_best_effort_info(tmp_path: Path) -> None:
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="example:latest",
        manifest_path=tmp_path / "trust_manifest.yaml",
        output_dir=tmp_path / "out",
    )
    ctx = TrustScanContext(config=config)

    findings = await StaticManifestCheck().run(ctx)

    assert any(f.passed and f.title == "Trust manifest not provided" for f in findings)


@pytest.mark.asyncio
async def test_manifest_valid_reports_pass(tmp_path: Path) -> None:
    manifest = tmp_path / "trust_manifest.yaml"
    manifest.write_text(
        "\n".join(
            [
                "submission_id: sub-123",
                "agent_name: listingpro",
                "entrypoint: app.main",
                "declared_external_domains:",
                "  - api.promptshop.com",
            ]
        )
    )

    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="example@sha256:1234",
        manifest_path=manifest,
        output_dir=tmp_path / "out",
    )
    ctx = TrustScanContext(config=config)

    findings = await StaticManifestCheck().run(ctx)

    assert any(f.passed and "parsed successfully" in f.title.lower() for f in findings)
