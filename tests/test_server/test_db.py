import pytest
from unittest.mock import AsyncMock

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
    mock_pool = AsyncMock()
    mock_pool.execute = AsyncMock()
    db.pool = mock_pool
    scan_id = await db.create_scan(
        scan_id="scan_abc123", repo_url="https://github.com/test/agent",
        entrypoint="main.py", runtime="python", manifest_path=None,
        webhook_url=None, api_key_id="ps001", idempotency_key=None,
    )
    assert scan_id == "scan_abc123"
    mock_pool.execute.assert_called_once()


@pytest.mark.asyncio
async def test_database_get_scan():
    db = Database(dsn="postgresql://test:test@localhost:5432/test")
    mock_pool = AsyncMock()
    mock_pool.fetchrow = AsyncMock(return_value={
        "id": "scan_abc123", "status": "pending",
        "repo_url": "https://github.com/test/agent", "api_key_id": "ps001", "verdict": None,
    })
    db.pool = mock_pool
    row = await db.get_scan("scan_abc123", api_key_id="ps001")
    assert row["id"] == "scan_abc123"
    assert row["status"] == "pending"


@pytest.mark.asyncio
async def test_database_get_scan_wrong_key():
    db = Database(dsn="postgresql://test:test@localhost:5432/test")
    mock_pool = AsyncMock()
    mock_pool.fetchrow = AsyncMock(return_value=None)
    db.pool = mock_pool
    row = await db.get_scan("scan_abc123", api_key_id="wrong_key")
    assert row is None
