import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport

from agentgate.server.app import create_app
from agentgate.server.models import ScanStatus


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.get_api_key = AsyncMock(return_value={
        "key_id": "testkey1",
        "key_hash": "$2b$12$test_hash",
        "name": "Test Key",
    })
    db.list_scan_events = AsyncMock(return_value=[])
    db.pool = AsyncMock()
    db.pool.fetchval = AsyncMock(return_value=1)
    return db


@pytest.fixture
def mock_redis():
    redis = AsyncMock()
    redis.ping = AsyncMock(return_value=True)
    return redis


@pytest.fixture
def app(mock_db, mock_redis):
    application = create_app()
    application.state.db = mock_db
    application.state.redis = mock_redis
    application.state.webhook_secret = "whsec_test"
    return application


@pytest.mark.asyncio
async def test_lifespan_skips_injected_resources(mock_db, mock_redis):
    """When db and redis are injected before startup, lifespan must not close them on shutdown."""
    application = create_app()
    application.state.db = mock_db
    application.state.redis = mock_redis
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/v1/health")
        assert resp.status_code == 200
    mock_db.disconnect.assert_not_awaited()
    mock_redis.close.assert_not_awaited()


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


@pytest.mark.asyncio
async def test_create_scan_enqueues_dockerfile_path(app, mock_db, mock_redis):
    mock_db.create_scan = AsyncMock()
    mock_db.get_scan = AsyncMock(return_value={
        "id": "scan_abc123",
        "status": ScanStatus.PENDING.value,
        "phase": "queued",
        "status_detail": "Scan accepted and queued for processing.",
        "progress_current": 0,
        "progress_total": 0,
        "repo_url": "https://github.com/test/agent",
        "git_ref": "feature/hosted-api",
        "dockerfile_path": "Dockerfile.api",
        "created_at": "2026-03-28T00:00:00Z",
        "updated_at": "2026-03-28T00:00:00Z",
        "verdict": None,
        "score": None,
        "error": None,
        "report": None,
        "completed_at": None,
    })
    transport = ASGITransport(app=app)
    with patch("agentgate.server.routes.scans.verify_secret", return_value=True):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/scans",
                json={
                    "repo_url": "https://github.com/test/agent",
                    "git_ref": "feature/hosted-api",
                    "dockerfile_path": "Dockerfile.api",
                },
                headers={"X-API-Key": "agk_live_testkey1.secret"},
            )
    assert resp.status_code == 201
    mock_db.create_scan.assert_awaited_once()
    _, kwargs = mock_db.create_scan.await_args
    assert kwargs["git_ref"] == "feature/hosted-api"
    assert kwargs["dockerfile_path"] == "Dockerfile.api"
    mock_redis.enqueue_job.assert_awaited_once()
    _, kwargs = mock_redis.enqueue_job.await_args
    assert kwargs["git_ref"] == "feature/hosted-api"
    assert kwargs["dockerfile_path"] == "Dockerfile.api"


@pytest.mark.asyncio
async def test_get_scan_events_returns_json_timeline(app, mock_db):
    mock_db.get_scan = AsyncMock(return_value={
        "id": "scan_abc123",
        "status": ScanStatus.SCANNING.value,
        "phase": "check_running",
        "status_detail": "Running trust check 'runtime_hosted'.",
        "progress_current": 3,
        "progress_total": 11,
        "repo_url": "https://github.com/test/agent",
        "created_at": "2026-03-28T00:00:00Z",
        "updated_at": "2026-03-28T00:00:10Z",
    })
    mock_db.list_scan_events = AsyncMock(return_value=[
        {
            "id": 1,
            "scan_id": "scan_abc123",
            "event_type": "scan.phase",
            "status": ScanStatus.CLONING.value,
            "phase": "clone_started",
            "detail": "Cloning the repository.",
            "progress_current": 0,
            "progress_total": 0,
            "payload": {"repo_url": "https://github.com/test/agent"},
            "created_at": "2026-03-28T00:00:01Z",
        }
    ])
    transport = ASGITransport(app=app)
    with patch("agentgate.server.routes.scans.verify_secret", return_value=True):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/v1/scans/scan_abc123/events",
                headers={"X-API-Key": "agk_live_testkey1.secret"},
            )
    assert resp.status_code == 200
    data = resp.json()
    assert data["scan_id"] == "scan_abc123"
    assert data["events"][0]["phase"] == "clone_started"


@pytest.mark.asyncio
async def test_get_scan_events_can_stream_sse(app, mock_db):
    terminal_scan = {
        "id": "scan_abc123",
        "status": ScanStatus.COMPLETED.value,
        "phase": "scan_completed",
        "status_detail": "Scan completed successfully.",
        "progress_current": 11,
        "progress_total": 11,
        "repo_url": "https://github.com/test/agent",
        "created_at": "2026-03-28T00:00:00Z",
        "updated_at": "2026-03-28T00:00:20Z",
    }
    mock_db.get_scan = AsyncMock(side_effect=[terminal_scan, terminal_scan])
    mock_db.list_scan_events = AsyncMock(return_value=[
        {
            "id": 3,
            "scan_id": "scan_abc123",
            "event_type": "scan.completed",
            "status": ScanStatus.COMPLETED.value,
            "phase": "scan_completed",
            "detail": "Scan completed successfully.",
            "progress_current": 11,
            "progress_total": 11,
            "payload": {"verdict": "allow_clean"},
            "created_at": "2026-03-28T00:00:20Z",
        }
    ])
    transport = ASGITransport(app=app)
    with patch("agentgate.server.routes.scans.verify_secret", return_value=True):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/v1/scans/scan_abc123/events?stream=true",
                headers={"X-API-Key": "agk_live_testkey1.secret"},
            )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert "event: scan.completed" in resp.text


@pytest.mark.asyncio
async def test_get_scan_includes_coverage_fields(app, mock_db):
    mock_db.get_scan = AsyncMock(return_value={
        "id": "scan_abc123",
        "status": ScanStatus.COMPLETED.value,
        "phase": "scan_completed",
        "status_detail": "Scan completed with limitations: deployment failed.",
        "progress_current": 11,
        "progress_total": 11,
        "repo_url": "https://github.com/test/agent",
        "created_at": "2026-03-28T00:00:00Z",
        "updated_at": "2026-03-28T00:00:20Z",
        "verdict": "allow_clean",
        "score": {"checks_run": 11, "checks_passed": 11, "checks_failed": 0},
        "error": None,
        "report": {
            "coverage": {
                "level": "none",
                "notes": ["No hosted runtime trace was captured."],
                "exercised_surfaces": [],
                "skipped_surfaces": ["/", "/docs"],
            }
        },
        "completed_at": "2026-03-28T00:00:20Z",
    })
    transport = ASGITransport(app=app)
    with patch("agentgate.server.routes.scans.verify_secret", return_value=True):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/v1/scans/scan_abc123",
                headers={"X-API-Key": "agk_live_testkey1.secret"},
            )
    assert resp.status_code == 200
    data = resp.json()
    assert data["coverage_status"] == "limited"
    assert data["coverage_recommendation"] == "manual_review"
    assert "No hosted runtime trace was captured." in data["coverage_detail"]


@pytest.mark.asyncio
async def test_error_envelope_validation_error(app):
    """POST with invalid body returns 422 with error='validation_error'."""
    transport = ASGITransport(app=app)
    with patch("agentgate.server.routes.scans.verify_secret", return_value=True):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/scans",
                json={},  # missing required repo_url
                headers={"X-API-Key": "agk_live_testkey1.secret"},
            )
    assert resp.status_code == 422
    data = resp.json()
    assert data["error"] == "validation_error"
    assert "detail" in data


@pytest.mark.asyncio
async def test_error_envelope_unauthorized(app):
    """Request without auth returns 401 with error='unauthorized'."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/scans",
            json={"repo_url": "https://github.com/test/agent"},
        )
    assert resp.status_code == 401
    data = resp.json()
    assert data["error"] == "unauthorized"
    assert "detail" in data


@pytest.mark.asyncio
async def test_error_envelope_not_found(app, mock_db):
    """GET a nonexistent scan returns 404 with error='not_found'."""
    mock_db.get_scan = AsyncMock(return_value=None)
    transport = ASGITransport(app=app)
    with patch("agentgate.server.routes.scans.verify_secret", return_value=True):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/v1/scans/scan_nonexistent",
                headers={"X-API-Key": "agk_live_testkey1.secret"},
            )
    assert resp.status_code == 404
    data = resp.json()
    assert data["error"] == "not_found"
    assert "detail" in data


@pytest.mark.asyncio
async def test_health_returns_503_when_db_unavailable(mock_redis):
    """Health returns 503 when the DB pool query fails."""
    db = AsyncMock()
    db.pool = AsyncMock()
    db.pool.fetchval = AsyncMock(side_effect=Exception("connection refused"))
    application = create_app()
    application.state.db = db
    application.state.redis = mock_redis
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/v1/health")
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_health_returns_503_when_redis_unavailable(mock_db):
    """Health returns 503 when Redis ping fails."""
    redis = AsyncMock()
    redis.ping = AsyncMock(side_effect=Exception("connection refused"))
    application = create_app()
    application.state.db = mock_db
    application.state.redis = redis
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/v1/health")
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_health_returns_200_when_both_healthy(app):
    """Health returns 200 when both DB and Redis respond normally."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
