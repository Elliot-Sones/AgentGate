from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from agentgate.server.routes.health import router as health_router
from agentgate.server.routes.scans import router as scans_router
from agentgate.server.urls import resolve_public_base_url

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    database_url = os.environ.get("DATABASE_URL", "")
    redis_url = os.environ.get("REDIS_URL", "")
    webhook_secret = os.environ.get("AGENTGATE_WEBHOOK_SECRET", "")
    public_base_url = resolve_public_base_url(os.environ)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owns_db = False
        owns_redis = False
        if getattr(app.state, "db", None) is None:
            if not database_url:
                raise RuntimeError("DATABASE_URL is required for the hosted API service.")
            from agentgate.server.db import Database
            db = Database(dsn=database_url)
            await db.connect()
            await db.run_migrations()
            app.state.db = db
            owns_db = True
        if getattr(app.state, "redis", None) is None:
            if not redis_url:
                raise RuntimeError("REDIS_URL is required for the hosted API service.")
            from arq import create_pool
            from arq.connections import RedisSettings
            app.state.redis = await create_pool(RedisSettings.from_dsn(redis_url))
            owns_redis = True
        app.state.webhook_secret = webhook_secret
        app.state.public_base_url = public_base_url
        yield
        if owns_db:
            db = getattr(app.state, "db", None)
            if db:
                await db.disconnect()
        if owns_redis:
            redis = getattr(app.state, "redis", None)
            if redis:
                await redis.close()

    app = FastAPI(
        title="AgentGate Trust Scanning API",
        version="2.0.0",
        description="Hosted trust verification for AI agent marketplaces",
        lifespan=lifespan,
    )

    app.include_router(health_router)
    app.include_router(scans_router)

    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    from agentgate.server.routes.scans import limiter as scans_limiter

    app.state.limiter = scans_limiter
    app.add_middleware(SlowAPIMiddleware)

    from fastapi.middleware.cors import CORSMiddleware

    cors_origins_raw = os.environ.get("AGENTGATE_CORS_ORIGINS", "")
    if cors_origins_raw.strip():
        origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request, exc):
        return JSONResponse(
            status_code=429,
            content={"error": "rate_limited", "detail": f"Rate limit exceeded: {exc.detail}"},
        )

    _HTTP_ERROR_CODES = {
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        409: "conflict",
        429: "rate_limited",
        503: "service_unavailable",
    }

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request, exc):
        details = []
        for error in exc.errors():
            field = ".".join(
                str(loc) for loc in error.get("loc", []) if loc != "body"
            )
            details.append(f"{field}: {error['msg']}" if field else error["msg"])
        return JSONResponse(
            status_code=422,
            content={"error": "validation_error", "detail": "; ".join(details)},
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request, exc):
        code = _HTTP_ERROR_CODES.get(exc.status_code, "api_error")
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": code, "detail": str(exc.detail)},
        )

    @app.exception_handler(Exception)
    async def catch_all_handler(request, exc):
        logger.error("Unhandled server exception: %s", exc, exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "detail": "An unexpected error occurred."},
        )

    return app
