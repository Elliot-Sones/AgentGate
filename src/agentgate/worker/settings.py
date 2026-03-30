from __future__ import annotations

import logging
import os
from pathlib import Path

from arq.connections import RedisSettings

from agentgate.server.db import Database
from agentgate.server.urls import resolve_public_base_url
from agentgate.services.scan_runner import ScanRunner
from agentgate.trust.runtime.railway_auth import (
    ensure_linked_railway_workspace,
    materialize_railway_cli_config,
)
from agentgate.worker.tasks import run_scan_job

logger = logging.getLogger(__name__)


REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/agentgate")
WORK_DIR = Path(os.environ.get("AGENTGATE_WORK_DIR", "/tmp/agentgate-scans"))
WEBHOOK_SECRET = os.environ.get("AGENTGATE_WEBHOOK_SECRET", "")
RAILWAY_WORKSPACE_ID = os.environ.get("AGENTGATE_RAILWAY_WORKSPACE_ID", "")
RAILWAY_POOL_DIR = os.environ.get("AGENTGATE_RAILWAY_POOL_DIR", "")
RAILWAY_POOL_ENV = os.environ.get("AGENTGATE_RAILWAY_POOL_ENVIRONMENT", "")
RAILWAY_POOL_SERVICE = os.environ.get("AGENTGATE_RAILWAY_POOL_SERVICE", "submission-agent")
RAILWAY_POOL_PROJECT_ID = (
    os.environ.get("AGENTGATE_RAILWAY_POOL_PROJECT_ID", "").strip()
    or os.environ.get("RAILWAY_PROJECT_ID", "").strip()
)
RAILWAY_CLI_CONFIG_B64 = os.environ.get("AGENTGATE_RAILWAY_CLI_CONFIG_B64", "")
RAILWAY_CLI_CONFIG_JSON = os.environ.get("AGENTGATE_RAILWAY_CLI_CONFIG_JSON", "")
RAILWAY_PROJECT_TOKEN = (
    os.environ.get("AGENTGATE_RAILWAY_PROJECT_TOKEN", "").strip()
    or os.environ.get("RAILWAY_TOKEN", "").strip()
)
ADAPTIVE_TRUST = os.environ.get("AGENTGATE_ADAPTIVE_TRUST", "1") == "1"
PUBLIC_BASE_URL = resolve_public_base_url(os.environ)
POOL_MODE_REQUESTED = bool(
    RAILWAY_POOL_DIR.strip() or RAILWAY_POOL_PROJECT_ID or RAILWAY_POOL_ENV.strip()
)


async def startup(ctx: dict) -> None:
    materialized_cli_config = materialize_railway_cli_config(
        config_b64=RAILWAY_CLI_CONFIG_B64,
        config_json=RAILWAY_CLI_CONFIG_JSON,
    )
    if materialized_cli_config:
        # Prefer Railway's file-based CLI session when present; it is more reliable than
        # injecting a raw RAILWAY_TOKEN value in this deployment.
        os.environ.pop("RAILWAY_TOKEN", None)
        os.environ.pop("AGENTGATE_RAILWAY_PROJECT_TOKEN", None)

    db = Database(dsn=DATABASE_URL)
    await db.connect()

    project_token = "" if materialized_cli_config else RAILWAY_PROJECT_TOKEN
    pool_workspace_dir = prepare_pool_workspace(project_token=project_token)

    ctx["db"] = db
    ctx["scan_runner"] = ScanRunner(
        work_dir=WORK_DIR,
        railway_workspace_id=RAILWAY_WORKSPACE_ID,
        railway_pool_workspace_dir=pool_workspace_dir,
        railway_pool_environment=RAILWAY_POOL_ENV,
        railway_pool_service=RAILWAY_POOL_SERVICE,
        adaptive_trust=ADAPTIVE_TRUST,
    )
    ctx["webhook_secret"] = WEBHOOK_SECRET
    ctx["public_base_url"] = PUBLIC_BASE_URL


def prepare_pool_workspace(*, project_token: str = "") -> Path | None:
    if not POOL_MODE_REQUESTED:
        return None

    raw_pool_dir = RAILWAY_POOL_DIR.strip()
    workspace_dir = Path(raw_pool_dir) if raw_pool_dir else (WORK_DIR / "railway-pool")
    workspace_dir.mkdir(parents=True, exist_ok=True)
    try:
        return ensure_linked_railway_workspace(
            workspace_dir=workspace_dir,
            project_id=RAILWAY_POOL_PROJECT_ID,
            environment=RAILWAY_POOL_ENV,
            project_token=project_token,
        )
    except RuntimeError as exc:
        raise RuntimeError(f"Railway pool bootstrap failed: {exc}") from exc


async def on_job_timeout(ctx: dict, job) -> None:
    """Write a terminal status when arq kills a job for exceeding job_timeout."""
    db: Database | None = ctx.get("db")
    if db is None:
        return
    scan_id = (job.kwargs or {}).get("scan_id", "")
    if not scan_id:
        return
    logger.error("Scan %s exceeded job_timeout and was killed by the worker.", scan_id)
    try:
        from datetime import datetime, timezone
        await db.record_scan_event(
            scan_id,
            status="failed",
            phase="worker_timeout",
            detail="Scan exceeded the maximum allowed time and was terminated.",
            event_type="scan.failed",
            fields={
                "error": "Scan timed out after exceeding the worker job timeout.",
                "completed_at": datetime.now(timezone.utc),
            },
        )
    except Exception:
        logger.exception("Failed to record timeout status for scan %s", scan_id)


async def shutdown(ctx: dict) -> None:
    db: Database = ctx.get("db")
    if db:
        await db.disconnect()


class WorkerSettings:
    functions = [run_scan_job]
    on_startup = startup
    on_shutdown = shutdown
    on_job_timeout = on_job_timeout
    redis_settings = RedisSettings.from_dsn(REDIS_URL)
    # A pooled Railway deployment currently reuses a single submission-agent service.
    # Keep the worker single-flight in pool mode so scans do not overwrite each other's deploys.
    max_jobs = 1 if POOL_MODE_REQUESTED else 2
    job_timeout = 900
