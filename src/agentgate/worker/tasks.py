from __future__ import annotations

from copy import deepcopy
import logging
from datetime import datetime, timezone

from agentgate.server.db import Database
from agentgate.server.urls import build_report_url
from agentgate.server.webhook import deliver_webhook, summarize_coverage_fields
from agentgate.services.scan_runner import ScanRunner

logger = logging.getLogger(__name__)


async def _record_progress(
    db: Database,
    scan_id: str,
    *,
    status: str,
    phase: str,
    detail: str,
    event_type: str = "scan.progress",
    progress_current: int | None = None,
    progress_total: int | None = None,
    payload: dict | None = None,
    fields: dict[str, object] | None = None,
) -> None:
    await db.record_scan_event(
        scan_id,
        status=status,
        phase=phase,
        detail=detail,
        event_type=event_type,
        progress_current=progress_current,
        progress_total=progress_total,
        payload=payload,
        fields=fields,
    )


async def run_scan_job(
    ctx: dict,
    *,
    scan_id: str,
    repo_url: str,
    git_ref: str | None,
    entrypoint: str | None,
    runtime: str,
    manifest_path: str | None,
    dockerfile_path: str | None,
) -> None:
    db: Database = ctx["db"]
    runner: ScanRunner = ctx["scan_runner"]
    webhook_secret: str = ctx["webhook_secret"]
    now = datetime.now(timezone.utc)

    try:
        logger.info("Starting scan %s for %s", scan_id, repo_url)
        await _record_progress(
            db,
            scan_id,
            status="cloning",
            phase="clone_started",
            detail="Cloning the repository.",
            event_type="scan.phase",
            fields={"started_at": now},
        )
        source_dir = await runner.clone_repo(repo_url=repo_url, git_ref=git_ref, scan_id=scan_id)
        await _record_progress(
            db,
            scan_id,
            status="cloning",
            phase="clone_completed",
            detail="Repository clone completed.",
            event_type="scan.phase",
            payload={"source_dir": str(source_dir)},
        )

        output_dir = runner.work_dir / scan_id / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        config = runner.build_trust_config(
            source_dir=source_dir,
            manifest_path=manifest_path,
            dockerfile_path=dockerfile_path,
            output_dir=output_dir,
        )

        if config.hosted_url:
            await _record_progress(
                db,
                scan_id,
                status="scanning",
                phase="hosted_target_ready",
                detail="Using the provided hosted URL and starting trust checks.",
                event_type="scan.phase",
                payload={"hosted_url": config.hosted_url},
            )
        else:
            await _record_progress(
                db,
                scan_id,
                status="deploying",
                phase="deployment_preparing",
                detail="Preparing the Railway deployment plan.",
                event_type="scan.phase",
            )

        async def _runner_event_callback(event: dict[str, object]) -> None:
            await db.record_scan_event(scan_id, **event)

        result = await runner.run_scan(config, event_callback=_runner_event_callback)

        completed_at = datetime.now(timezone.utc)
        report = deepcopy(result.report)
        if not isinstance(report, dict):
            report = {}
        failure_reason = getattr(result, "failure_reason", None)
        if failure_reason and not report.get("failure_reason"):
            report["failure_reason"] = failure_reason
        coverage_status, coverage_detail, coverage_recommendation = summarize_coverage_fields(
            report,
            verdict=result.verdict,
        )
        if coverage_status is not None:
            report["coverage_status"] = coverage_status
            report["coverage_recommendation"] = coverage_recommendation
            if coverage_detail is not None:
                report["coverage_detail"] = coverage_detail
            if isinstance(report.get("coverage"), dict):
                report["coverage"]["level"] = coverage_status
        update_fields: dict[str, object] = {
            "report": report,
            "completed_at": completed_at,
        }
        if result.terminal_status == "completed":
            update_fields["verdict"] = result.verdict
            update_fields["score"] = result.score
        if result.error:
            update_fields["error"] = result.error
        terminal_phase = "scan_completed" if result.terminal_status == "completed" else "scan_failed"
        if result.terminal_status == "completed":
            terminal_detail = (
                f"Scan completed with limitations: {result.error}"
                if result.error
                else "Scan completed successfully."
            )
        else:
            terminal_detail = result.error or "Scan failed."
        terminal_payload = {
            "verdict": result.verdict,
            "score": result.score,
        }
        await _record_progress(
            db,
            scan_id,
            status=result.terminal_status,
            phase=terminal_phase,
            detail=terminal_detail,
            event_type=f"scan.{result.terminal_status}",
            payload=terminal_payload,
            fields=update_fields,
        )
        logger.info("Finished scan %s with status %s", scan_id, result.terminal_status)

        scan_row = await db.get_scan_internal(scan_id)
        webhook_url = scan_row.get("webhook_url") if scan_row else None
        if webhook_url and webhook_secret and result.terminal_status == "completed":
            await deliver_webhook(
                webhook_url=webhook_url,
                scan_id=scan_id,
                verdict=result.verdict,
                score=result.score,
                coverage_status=coverage_status,
                coverage_recommendation=coverage_recommendation,
                report_url=build_report_url(scan_id, ctx.get("public_base_url", "")),
                webhook_secret=webhook_secret,
            )

    except Exception as exc:
        logger.exception("Scan %s failed: %s", scan_id, exc)
        await _record_progress(
            db,
            scan_id,
            status="failed",
            phase="worker_error",
            detail=str(exc),
            event_type="scan.failed",
            fields={
                "error": str(exc),
                "completed_at": datetime.now(timezone.utc),
            },
        )
    finally:
        runner.cleanup(scan_id)
