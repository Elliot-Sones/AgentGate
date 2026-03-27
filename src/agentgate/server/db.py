from __future__ import annotations

import json
from datetime import datetime, timezone

import asyncpg


class Database:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self.pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        self.pool = await asyncpg.create_pool(self.dsn, min_size=2, max_size=10)

    async def disconnect(self) -> None:
        if self.pool:
            await self.pool.close()

    async def run_migrations(self) -> None:
        from pathlib import Path
        migration_file = Path(__file__).parent.parent / "migrations" / "001_initial.sql"
        sql = migration_file.read_text()
        assert self.pool is not None
        await self.pool.execute(sql)

    async def create_scan(
        self, *, scan_id: str, repo_url: str, entrypoint: str | None,
        runtime: str, manifest_path: str | None, webhook_url: str | None,
        api_key_id: str, idempotency_key: str | None,
    ) -> str:
        assert self.pool is not None
        await self.pool.execute(
            """INSERT INTO scans (id, status, repo_url, entrypoint, runtime, manifest_path,
                               webhook_url, api_key_id, idempotency_key)
            VALUES ($1, 'pending', $2, $3, $4, $5, $6, $7, $8)""",
            scan_id, repo_url, entrypoint, runtime, manifest_path,
            webhook_url, api_key_id, idempotency_key,
        )
        return scan_id

    async def find_by_idempotency_key(self, *, api_key_id: str, idempotency_key: str) -> dict | None:
        assert self.pool is not None
        row = await self.pool.fetchrow(
            "SELECT * FROM scans WHERE api_key_id = $1 AND idempotency_key = $2",
            api_key_id, idempotency_key,
        )
        return dict(row) if row else None

    async def get_scan(self, scan_id: str, *, api_key_id: str) -> dict | None:
        assert self.pool is not None
        row = await self.pool.fetchrow(
            "SELECT * FROM scans WHERE id = $1 AND api_key_id = $2",
            scan_id, api_key_id,
        )
        return dict(row) if row else None

    async def get_scan_internal(self, scan_id: str) -> dict | None:
        """Get scan without api_key scoping. For worker use only."""
        assert self.pool is not None
        row = await self.pool.fetchrow("SELECT * FROM scans WHERE id = $1", scan_id)
        return dict(row) if row else None

    async def list_scans(self, *, api_key_id: str, limit: int = 20, offset: int = 0) -> list[dict]:
        assert self.pool is not None
        rows = await self.pool.fetch(
            "SELECT * FROM scans WHERE api_key_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            api_key_id, limit, offset,
        )
        return [dict(r) for r in rows]

    async def update_scan_status(self, scan_id: str, *, status: str, **fields: object) -> None:
        assert self.pool is not None
        now = datetime.now(timezone.utc)
        sets = ["status = $2", "updated_at = $3"]
        args: list[object] = [scan_id, status, now]
        idx = 4
        for key, value in fields.items():
            if key in ("verdict", "error", "started_at", "completed_at"):
                sets.append(f"{key} = ${idx}")
                args.append(value)
                idx += 1
            elif key in ("score", "report"):
                sets.append(f"{key} = ${idx}")
                args.append(json.dumps(value) if isinstance(value, dict) else value)
                idx += 1
        sql = f"UPDATE scans SET {', '.join(sets)} WHERE id = $1"
        await self.pool.execute(sql, *args)

    async def get_api_key(self, key_id: str) -> dict | None:
        assert self.pool is not None
        row = await self.pool.fetchrow("SELECT * FROM api_keys WHERE key_id = $1", key_id)
        return dict(row) if row else None

    async def create_api_key(self, *, key_id: str, key_hash: str, name: str) -> None:
        assert self.pool is not None
        await self.pool.execute(
            "INSERT INTO api_keys (key_id, key_hash, name) VALUES ($1, $2, $3)",
            key_id, key_hash, name,
        )
