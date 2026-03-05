from __future__ import annotations

from pathlib import Path

import pytest

from agentscorer.trust.checks.base import BaseTrustCheck
from agentscorer.trust.config import TrustScanConfig
from agentscorer.trust.context import TrustScanContext
from agentscorer.trust.models import TrustCategory, TrustFinding, TrustSeverity, TrustVerdict
from agentscorer.trust.scanner import TrustScanner


class PassingCheck(BaseTrustCheck):
    check_id = "passing_check"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        return [
            self.finding(
                title="pass",
                category=TrustCategory.DECLARATION,
                severity=TrustSeverity.INFO,
                passed=True,
                summary="ok",
            )
        ]


class CriticalCheck(BaseTrustCheck):
    check_id = "critical_check"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        return [
            self.finding(
                title="critical",
                category=TrustCategory.CANARY,
                severity=TrustSeverity.CRITICAL,
                passed=False,
                summary="bad",
            )
        ]


@pytest.mark.asyncio
async def test_trust_scanner_computes_block_verdict(tmp_path: Path) -> None:
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="example:latest",
        manifest_path=None,
        output_dir=tmp_path / "out",
    )
    scanner = TrustScanner(config=config, checks=[PassingCheck(), CriticalCheck()])

    result = await scanner.run()

    assert result.scorecard.verdict == TrustVerdict.BLOCK
    assert result.scorecard.checks_run == 2
    assert result.scorecard.checks_failed == 1
