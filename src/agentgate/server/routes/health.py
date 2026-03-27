from fastapi import APIRouter

from agentgate.server.models import HealthResponse

router = APIRouter()


@router.get("/v1/health", response_model=HealthResponse)
async def health():
    return HealthResponse()
