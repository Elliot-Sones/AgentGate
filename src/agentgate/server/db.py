from __future__ import annotations

import json
from datetime import datetime, timezone

import asyncpg


def _sanitize_for_postgres(value: object) -> object:
    """Strip null bytes that Postgres TEXT/JSONB columns reject."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {k: _sanitize_for_postgres(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_for_postgres(v) for v in value]
    return value


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

    @staticmethod
    def _normalize_scan_row(row: asyncpg.Record | dict | None) -> dict | None:
        if row is None:
            return None
        data = dict(row)
        for key in ("score", "report"):
            value = data.get(key)
            if isinstance(value, str):
                try:
                    data[key] = json.loads(value)
                except json.JSONDecodeError:
                    pass
        return data

    @staticmethod
    def _normalize_scan_event_row(row: asyncpg.Record | dict | None) -> dict | None:
        if row is None:
            return None
        data = dict(row)
        payload = data.get("payload")
        if isinstance(payload, str):
            try:
                data["payload"] = json.loads(payload)
            except json.JSONDecodeError:
                pass
        return data

    async def create_scan(
        self, *, scan_id: str, repo_url: str, git_ref: str | None, entrypoint: str | None,
        runtime: str, manifest_path: str | None, dockerfile_path: str | None, webhook_url: str | None,
        api_key_id: str, idempotency_key: str | None,
    ) -> str:
        assert self.pool is not None
        now = datetime.now(timezone.utc)
        detail = "Scan accepted and queued for processing."
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    """INSERT INTO scans (
                        id, status, phase, status_detail, progress_current, progress_total, repo_url,
                        git_ref, entrypoint, runtime, manifest_path, dockerfile_path, webhook_url,
                        api_key_id, idempotency_key, created_at, updated_at
                    )
                    VALUES (
                        $1, 'pending', 'queued', $2, 0, 0, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12
                    )""",
                    scan_id,
                    detail,
                    repo_url,
                    git_ref,
                    entrypoint,
                    runtime,
                    manifest_path,
                    dockerfile_path,
                    webhook_url,
                    api_key_id,
                    idempotency_key,
                    now,
                )
                await conn.execute(
                    """INSERT INTO scan_events (
                        scan_id, event_type, status, phase, detail, progress_current, progress_total, payload, created_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)""",
                    scan_id,
                    "scan.created",
                    "pending",
                    "queued",
                    detail,
                    0,
                    0,
                    json.dumps({"repo_url": repo_url, "git_ref": git_ref, "dockerfile_path": dockerfile_path}),
                    now,
                )
        return scan_id

    async def find_by_idempotency_key(self, *, api_key_id: str, idempotency_key: str) -> dict | None:
        assert self.pool is not None
        row = await self.pool.fetchrow(
            "SELECT * FROM scans WHERE api_key_id = $1 AND idempotency_key = $2",
            api_key_id, idempotency_key,
        )
        return self._normalize_scan_row(row)

    async def get_scan(self, scan_id: str, *, api_key_id: str) -> dict | None:
        assert self.pool is not None
        row = await self.pool.fetchrow(
            "SELECT * FROM scans WHERE id = $1 AND api_key_id = $2",
            scan_id, api_key_id,
        )
        return self._normalize_scan_row(row)

    async def get_scan_internal(self, scan_id: str) -> dict | None:
        """Get scan without api_key scoping. For worker use only."""
        assert self.pool is not None
        row = await self.pool.fetchrow("SELECT * FROM scans WHERE id = $1", scan_id)
        return self._normalize_scan_row(row)

    async def list_scans(self, *, api_key_id: str, limit: int = 20, offset: int = 0) -> list[dict]:
        assert self.pool is not None
        rows = await self.pool.fetch(
            "SELECT * FROM scans WHERE api_key_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            api_key_id, limit, offset,
        )
        return [self._normalize_scan_row(r) for r in rows if r is not None]

    async def update_scan_status(self, scan_id: str, *, status: str, **fields: object) -> None:
        assert self.pool is not None
        now = datetime.now(timezone.utc)
        await self._execute_scan_update(self.pool, scan_id, status=status, now=now, fields=fields)

    async def record_scan_event(
        self,
        scan_id: str,
        *,
        status: str,
        phase: str = "",
        detail: str = "",
        event_type: str = "scan.progress",
        progress_current: int | None = None,
        progress_total: int | None = None,
        payload: dict | None = None,
        fields: dict[str, object] | None = None,
    ) -> dict:
        assert self.pool is not None
        now = datetime.now(timezone.utc)
        update_fields = dict(fields or {})
        if phase:
            update_fields.setdefault("phase", phase)
        if detail:
            update_fields.setdefault("status_detail", detail)
        if progress_current is not None:
            update_fields.setdefault("progress_current", progress_current)
        if progress_total is not None:
            update_fields.setdefault("progress_total", progress_total)

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await self._execute_scan_update(conn, scan_id, status=status, now=now, fields=update_fields)
                sanitized_detail = _sanitize_for_postgres(detail) if detail else None
                sanitized_payload = json.dumps(_sanitize_for_postgres(payload)) if payload is not None else None
                row = await conn.fetchrow(
                    """INSERT INTO scan_events (
                        scan_id, event_type, status, phase, detail, progress_current, progress_total, payload, created_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)
                    RETURNING id, scan_id, event_type, status, phase, detail,
                              progress_current, progress_total, payload, created_at""",
                    scan_id,
                    event_type,
                    status,
                    phase or None,
                    sanitized_detail,
                    progress_current,
                    progress_total,
                    sanitized_payload,
                    now,
                )
        return self._normalize_scan_event_row(row) or {}

    async def list_scan_events(
        self,
        scan_id: str,
        *,
        after_id: int = 0,
        limit: int = 200,
    ) -> list[dict]:
        assert self.pool is not None
        rows = await self.pool.fetch(
            """SELECT id, scan_id, event_type, status, phase, detail, progress_current,
                      progress_total, payload, created_at
               FROM scan_events
               WHERE scan_id = $1 AND id > $2
               ORDER BY id ASC
               LIMIT $3""",
            scan_id,
            after_id,
            limit,
        )
        return [self._normalize_scan_event_row(r) for r in rows if r is not None]

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

    async def _execute_scan_update(
        self,
        executor,
        scan_id: str,
        *,
        status: str,
        now: datetime,
        fields: dict[str, object],
    ) -> None:
        sets = ["status = $2", "updated_at = $3"]
        args: list[object] = [scan_id, status, now]
        idx = 4
        for key, value in fields.items():
            if key in (
                "verdict",
                "error",
                "started_at",
                "completed_at",
                "phase",
                "status_detail",
                "progress_current",
                "progress_total",
            ):
                sets.append(f"{key} = ${idx}")
                args.append(_sanitize_for_postgres(value))
                idx += 1
            elif key in ("score", "report"):
                sets.append(f"{key} = ${idx}")
                sanitized = _sanitize_for_postgres(value)
                args.append(json.dumps(sanitized) if isinstance(sanitized, dict) else sanitized)
                idx += 1
        sql = f"UPDATE scans SET {', '.join(sets)} WHERE id = $1"
        await executor.execute(sql, *args)
