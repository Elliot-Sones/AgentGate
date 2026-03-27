from __future__ import annotations

import os
from pathlib import Path

from arq.connections import RedisSettings

from agentgate.server.db import Database
from agentgate.services.scan_runner import ScanRunner


REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/agentgate")
WORK_DIR = Path(os.environ.get("AGENTGATE_WORK_DIR", "/tmp/agentgate-scans"))
WEBHOOK_SECRET = os.environ.get("AGENTGATE_WEBHOOK_SECRET", "")


async def startup(ctx: dict) -> None:
    db = Database(dsn=DATABASE_URL)
    await db.connect()
    ctx["db"] = db
    ctx["scan_runner"] = ScanRunner(work_dir=WORK_DIR)
    ctx["webhook_secret"] = WEBHOOK_SECRET


async def shutdown(ctx: dict) -> None:
    db: Database = ctx.get("db")
    if db:
        await db.disconnect()


class WorkerSettings:
    functions = ["agentgate.worker.tasks.run_scan_job"]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(REDIS_URL)
    max_jobs = 2
    job_timeout = 600
