import pytest
from unittest.mock import AsyncMock
from httpx import AsyncClient, ASGITransport

from agentgate.server.app import create_app


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.get_api_key = AsyncMock(return_value={
        "key_id": "testkey1",
        "key_hash": "$2b$12$test_hash",
        "name": "Test Key",
    })
    return db


@pytest.fixture
def mock_redis():
    return AsyncMock()


@pytest.fixture
def app(mock_db, mock_redis):
    application = create_app()
    application.state.db = mock_db
    application.state.redis = mock_redis
    application.state.webhook_secret = "whsec_test"
    return application


@pytest.mark.asyncio
async def test_health_endpoint(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_create_scan_no_auth(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/v1/scans", json={"repo_url": "https://github.com/test/agent"})
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_scan_invalid_key(app, mock_db):
    mock_db.get_api_key = AsyncMock(return_value=None)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/scans",
            json={"repo_url": "https://github.com/test/agent"},
            headers={"X-API-Key": "agk_live_badkey.badsecret"},
        )
        assert resp.status_code == 401
