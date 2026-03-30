from fastapi import APIRouter, HTTPException, Request

from agentgate.server.models import HealthResponse

router = APIRouter()


@router.get("/v1/health", response_model=HealthResponse)
async def health(request: Request):
    db = getattr(request.app.state, "db", None)
    redis = getattr(request.app.state, "redis", None)

    db_ok = False
    if db is not None:
        pool = getattr(db, "pool", None)
        if pool is not None:
            try:
                await pool.fetchval("SELECT 1")
                db_ok = True
            except Exception:
                pass

    redis_ok = False
    if redis is not None:
        try:
            await redis.ping()
            redis_ok = True
        except Exception:
            pass

    if not (db_ok and redis_ok):
        raise HTTPException(status_code=503, detail="Service dependencies unavailable")

    return HealthResponse()
