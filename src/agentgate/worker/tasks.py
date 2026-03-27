from __future__ import annotations

import logging
from datetime import datetime, timezone

from agentgate.server.db import Database
from agentgate.server.webhook import deliver_webhook
from agentgate.services.scan_runner import ScanRunner

logger = logging.getLogger(__name__)


async def run_scan_job(
    ctx: dict,
    *,
    scan_id: str,
    repo_url: str,
    entrypoint: str | None,
    runtime: str,
    manifest_path: str | None,
) -> None:
    db: Database = ctx["db"]
    runner: ScanRunner = ctx["scan_runner"]
    webhook_secret: str = ctx["webhook_secret"]
    now = datetime.now(timezone.utc)

    try:
        await db.update_scan_status(scan_id, status="cloning", started_at=now)
        source_dir = await runner.clone_repo(repo_url=repo_url, scan_id=scan_id)

        output_dir = runner.work_dir / scan_id / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        config = runner.build_trust_config(
            source_dir=source_dir, manifest_path=manifest_path, output_dir=output_dir,
        )

        await db.update_scan_status(scan_id, status="scanning")
        result = await runner.run_scan(config)

        completed_at = datetime.now(timezone.utc)
        await db.update_scan_status(
            scan_id, status="completed", verdict=result.verdict,
            score=result.score, report=result.report, completed_at=completed_at,
        )

        scan_row = await db.get_scan_internal(scan_id)
        webhook_url = scan_row.get("webhook_url") if scan_row else None
        if webhook_url and webhook_secret:
            await deliver_webhook(
                webhook_url=webhook_url, scan_id=scan_id, verdict=result.verdict,
                score=result.score, report_url=f"/v1/scans/{scan_id}/report",
                webhook_secret=webhook_secret,
            )

    except Exception as exc:
        logger.exception("Scan %s failed: %s", scan_id, exc)
        await db.update_scan_status(
            scan_id, status="failed", error=str(exc),
            completed_at=datetime.now(timezone.utc),
        )
    finally:
        runner.cleanup(scan_id)
