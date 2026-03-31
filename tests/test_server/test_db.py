import pytest
from unittest.mock import AsyncMock, MagicMock

from agentgate.server.db import Database


@pytest.fixture
def db():
    return Database(dsn="postgresql://test:test@localhost:5432/test")


def test_database_init(db):
    assert db.dsn == "postgresql://test:test@localhost:5432/test"
    assert db.pool is None


@pytest.mark.asyncio
async def test_database_create_scan():
    db = Database(dsn="postgresql://test:test@localhost:5432/test")
    mock_conn = MagicMock()
    mock_conn.execute = AsyncMock()
    transaction = MagicMock()
    transaction.__aenter__ = AsyncMock(return_value=None)
    transaction.__aexit__ = AsyncMock(return_value=None)
    mock_conn.transaction.return_value = transaction
    acquire_ctx = MagicMock()
    acquire_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    acquire_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_pool = MagicMock()
    mock_pool.acquire.return_value = acquire_ctx
    db.pool = mock_pool
    scan_id = await db.create_scan(
        scan_id="scan_abc123", repo_url="https://github.com/test/agent",
        git_ref="feature/hosted-api", entrypoint="main.py", runtime="python", manifest_path=None,
        dockerfile_path="Dockerfile.api", webhook_url=None, api_key_id="ps001", idempotency_key=None,
    )
    assert scan_id == "scan_abc123"
    assert mock_conn.execute.await_count == 2


@pytest.mark.asyncio
async def test_database_get_scan():
    db = Database(dsn="postgresql://test:test@localhost:5432/test")
    mock_pool = AsyncMock()
    mock_pool.fetchrow = AsyncMock(return_value={
        "id": "scan_abc123", "status": "pending",
        "repo_url": "https://github.com/test/agent", "api_key_id": "ps001", "verdict": None,
        "score": '{"checks_run": 1, "checks_passed": 1, "checks_failed": 0}',
    })
    db.pool = mock_pool
    row = await db.get_scan("scan_abc123", api_key_id="ps001")
    assert row["id"] == "scan_abc123"
    assert row["status"] == "pending"
    assert row["score"]["checks_run"] == 1


@pytest.mark.asyncio
async def test_database_get_scan_wrong_key():
    db = Database(dsn="postgresql://test:test@localhost:5432/test")
    mock_pool = AsyncMock()
    mock_pool.fetchrow = AsyncMock(return_value=None)
    db.pool = mock_pool
    row = await db.get_scan("scan_abc123", api_key_id="wrong_key")
    assert row is None


@pytest.mark.asyncio
async def test_database_record_scan_event_updates_scan_and_inserts_event():
    db = Database(dsn="postgresql://test:test@localhost:5432/test")
    mock_conn = MagicMock()
    mock_conn.execute = AsyncMock()
    mock_conn.fetchrow = AsyncMock(
        return_value={
            "id": 7,
            "scan_id": "scan_abc123",
            "event_type": "scan.phase",
            "status": "cloning",
            "phase": "clone_started",
            "detail": "Cloning the repository.",
            "progress_current": 0,
            "progress_total": 0,
            "payload": '{"repo_url":"https://github.com/test/agent"}',
            "created_at": "2026-03-29T12:00:00Z",
        }
    )
    transaction = MagicMock()
    transaction.__aenter__ = AsyncMock(return_value=None)
    transaction.__aexit__ = AsyncMock(return_value=None)
    mock_conn.transaction.return_value = transaction
    acquire_ctx = MagicMock()
    acquire_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    acquire_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_pool = MagicMock()
    mock_pool.acquire.return_value = acquire_ctx
    db.pool = mock_pool

    event = await db.record_scan_event(
        "scan_abc123",
        status="cloning",
        phase="clone_started",
        detail="Cloning the repository.",
        payload={"repo_url": "https://github.com/test/agent"},
    )

    assert mock_conn.execute.await_count == 1
    assert event["payload"] == {"repo_url": "https://github.com/test/agent"}


@pytest.mark.asyncio
async def test_database_list_scan_events_normalizes_payload():
    db = Database(dsn="postgresql://test:test@localhost:5432/test")
    mock_pool = AsyncMock()
    mock_pool.fetch = AsyncMock(
        return_value=[
            {
                "id": 3,
                "scan_id": "scan_abc123",
                "event_type": "scan.phase",
                "status": "scanning",
                "phase": "check_completed",
                "detail": "Finished trust check 'runtime_hosted'.",
                "progress_current": 4,
                "progress_total": 11,
                "payload": '{"check_id":"runtime_hosted"}',
                "created_at": "2026-03-29T12:00:00Z",
            }
        ]
    )
    db.pool = mock_pool

    events = await db.list_scan_events("scan_abc123", after_id=0, limit=10)

    assert events[0]["payload"] == {"check_id": "runtime_hosted"}
