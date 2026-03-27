from __future__ import annotations

import os

from fastapi import FastAPI

from agentgate.server.routes.health import router as health_router
from agentgate.server.routes.scans import router as scans_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentGate Trust Scanning API",
        version="2.0.0",
        description="Hosted trust verification for AI agent marketplaces",
    )

    app.include_router(health_router)
    app.include_router(scans_router)

    database_url = os.environ.get("DATABASE_URL", "")
    redis_url = os.environ.get("REDIS_URL", "")
    webhook_secret = os.environ.get("AGENTGATE_WEBHOOK_SECRET", "")

    @app.on_event("startup")
    async def startup():
        if database_url:
            from agentgate.server.db import Database
            db = Database(dsn=database_url)
            await db.connect()
            await db.run_migrations()
            app.state.db = db

        if redis_url:
            from arq import create_pool
            from arq.connections import RedisSettings
            app.state.redis = await create_pool(RedisSettings.from_dsn(redis_url))

        app.state.webhook_secret = webhook_secret

    @app.on_event("shutdown")
    async def shutdown():
        db = getattr(app.state, "db", None)
        if db:
            await db.disconnect()
        redis = getattr(app.state, "redis", None)
        if redis:
            await redis.close()

    return app
