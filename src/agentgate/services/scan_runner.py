from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from agentgate.trust.config import TrustScanConfig
from agentgate.trust.models import TrustScanResult, TrustScorecard

logger = logging.getLogger(__name__)


@dataclass
class ScanRunResult:
    verdict: str
    score: dict
    report: dict
    error: str | None = None


class ScanRunner:
    def __init__(self, work_dir: Path) -> None:
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)

    async def clone_repo(self, *, repo_url: str, scan_id: str) -> Path:
        clone_dir = self.work_dir / scan_id / "repo"
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(clone_dir)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr.strip()}")
        return clone_dir

    def build_trust_config(
        self, *, source_dir: Path, manifest_path: str | None, output_dir: Path,
    ) -> TrustScanConfig:
        resolved_manifest = None
        if manifest_path:
            resolved_manifest = source_dir / manifest_path
            if not resolved_manifest.exists():
                resolved_manifest = None
        return TrustScanConfig(
            source_dir=source_dir, image_ref="", manifest_path=resolved_manifest,
            output_dir=output_dir, quiet=True,
        )

    async def run_scan(self, config: TrustScanConfig) -> ScanRunResult:
        from agentgate.trust.scanner import TrustScanner
        scanner = TrustScanner(config=config)
        result: TrustScanResult = await scanner.run()
        scorecard: TrustScorecard = result.scorecard
        score_dict = {
            "checks_run": scorecard.checks_run,
            "checks_passed": scorecard.checks_passed,
            "checks_failed": scorecard.checks_failed,
        }
        report_dict = result.model_dump(mode="json")
        return ScanRunResult(verdict=scorecard.verdict.value, score=score_dict, report=report_dict)

    def cleanup(self, scan_id: str) -> None:
        scan_dir = self.work_dir / scan_id
        if scan_dir.exists():
            shutil.rmtree(scan_dir, ignore_errors=True)
