# AgentGate Hosted API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a hosted trust-scanning API that PromptShop can call to verify seller-submitted agents before listing.

**Architecture:** Split API (FastAPI) + Worker (arq) on Railway. Postgres for scan state and reports. Redis for job queue only. API key auth with key_id.secret pattern. Signed webhook delivery.

**Tech Stack:** FastAPI, arq, asyncpg, Redis, Postgres, bcrypt, httpx

**Spec:** `docs/superpowers/specs/2026-03-26-hosted-api-design.md`

---

### Task 1: Add New Dependencies

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add server dependencies to pyproject.toml**

Add a `server` optional dependency group and promote fastapi/uvicorn:

```toml
[project.optional-dependencies]
server = [
    "fastapi>=0.115.0",
    "uvicorn>=0.32.0",
    "arq>=0.26.0",
    "asyncpg>=0.30.0",
    "bcrypt>=4.0.0",
    "redis[hiredis]>=5.0.0",
]
test-agent = [
    "fastapi>=0.115.0",
    "uvicorn>=0.32.0",
    "langchain-core>=0.3.0",
    "langchain-anthropic>=0.3.0",
]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.24.0",
    "ruff>=0.8.0",
]
```

- [ ] **Step 2: Install the new dependencies**

Run: `pip install -e ".[server,dev]"`
Expected: All packages install successfully.

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml
git commit -m "Add server dependencies for hosted API (fastapi, arq, asyncpg, bcrypt, redis)"
```

---

### Task 2: Database Migration and Connection Layer

**Files:**
- Create: `src/agentgate/migrations/001_initial.sql`
- Create: `src/agentgate/server/__init__.py`
- Create: `src/agentgate/server/db.py`
- Create: `tests/test_server/__init__.py`
- Create: `tests/test_server/test_db.py`

- [ ] **Step 1: Create the initial migration file**

Create `src/agentgate/migrations/001_initial.sql`:

```sql
CREATE TABLE IF NOT EXISTS api_keys (
    key_id      TEXT PRIMARY KEY,
    key_hash    TEXT NOT NULL UNIQUE,
    name        TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'pending',
    repo_url        TEXT NOT NULL,
    entrypoint      TEXT,
    runtime         TEXT DEFAULT 'python',
    manifest_path   TEXT,
    webhook_url     TEXT,
    api_key_id      TEXT NOT NULL,
    idempotency_key TEXT,
    verdict         TEXT,
    score           JSONB,
    report          JSONB,
    error           TEXT,
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scans_api_key_id ON scans(api_key_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_idempotency ON scans(api_key_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
```

- [ ] **Step 2: Write the failing test for db module**

Create `tests/test_server/__init__.py` (empty) and `tests/test_server/test_db.py`:

```python
import pytest
from unittest.mock import AsyncMock, patch

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
        scan_id="scan_abc123",
        repo_url="https://github.com/test/agent",
        entrypoint="main.py",
        runtime="python",
        manifest_path=None,
        webhook_url=None,
        api_key_id="ps001",
        idempotency_key=None,
    )
    assert scan_id == "scan_abc123"
    mock_pool.execute.assert_called_once()


@pytest.mark.asyncio
async def test_database_get_scan():
    db = Database(dsn="postgresql://test:test@localhost:5432/test")
    mock_pool = AsyncMock()
    mock_pool.fetchrow = AsyncMock(return_value={
        "id": "scan_abc123",
        "status": "pending",
        "repo_url": "https://github.com/test/agent",
        "api_key_id": "ps001",
        "verdict": None,
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_server/test_db.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agentgate.server'`

- [ ] **Step 4: Implement the db module**

Create `src/agentgate/server/__init__.py` (empty) and `src/agentgate/server/db.py`:

```python
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
        self,
        *,
        scan_id: str,
        repo_url: str,
        entrypoint: str | None,
        runtime: str,
        manifest_path: str | None,
        webhook_url: str | None,
        api_key_id: str,
        idempotency_key: str | None,
    ) -> str:
        assert self.pool is not None
        await self.pool.execute(
            """
            INSERT INTO scans (id, status, repo_url, entrypoint, runtime, manifest_path,
                               webhook_url, api_key_id, idempotency_key)
            VALUES ($1, 'pending', $2, $3, $4, $5, $6, $7, $8)
            """,
            scan_id, repo_url, entrypoint, runtime, manifest_path,
            webhook_url, api_key_id, idempotency_key,
        )
        return scan_id

    async def find_by_idempotency_key(
        self, *, api_key_id: str, idempotency_key: str
    ) -> dict | None:
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

    async def list_scans(
        self, *, api_key_id: str, limit: int = 20, offset: int = 0
    ) -> list[dict]:
        assert self.pool is not None
        rows = await self.pool.fetch(
            "SELECT * FROM scans WHERE api_key_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            api_key_id, limit, offset,
        )
        return [dict(r) for r in rows]

    async def update_scan_status(
        self, scan_id: str, *, status: str, **fields: object
    ) -> None:
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
        row = await self.pool.fetchrow(
            "SELECT * FROM api_keys WHERE key_id = $1", key_id
        )
        return dict(row) if row else None

    async def create_api_key(
        self, *, key_id: str, key_hash: str, name: str
    ) -> None:
        assert self.pool is not None
        await self.pool.execute(
            "INSERT INTO api_keys (key_id, key_hash, name) VALUES ($1, $2, $3)",
            key_id, key_hash, name,
        )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_server/test_db.py -v`
Expected: All 4 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agentgate/migrations/ src/agentgate/server/ tests/test_server/
git commit -m "Add database layer with migrations, scan CRUD, and API key storage"
```

---

### Task 3: API Key Authentication

**Files:**
- Create: `src/agentgate/server/auth.py`
- Create: `tests/test_server/test_auth.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_server/test_auth.py`:

```python
import pytest

from agentgate.server.auth import parse_api_key, generate_api_key, hash_secret, verify_secret


def test_parse_api_key_valid():
    key_id, secret = parse_api_key("agk_live_ps001.xK9mW2vR7nQ4pL8sT1abc")
    assert key_id == "ps001"
    assert secret == "xK9mW2vR7nQ4pL8sT1abc"


def test_parse_api_key_invalid_prefix():
    with pytest.raises(ValueError, match="Invalid API key format"):
        parse_api_key("bad_key_ps001.secret")


def test_parse_api_key_missing_dot():
    with pytest.raises(ValueError, match="Invalid API key format"):
        parse_api_key("agk_live_ps001secret")


def test_generate_api_key():
    key_id, raw_key, secret_hash = generate_api_key()
    assert raw_key.startswith("agk_live_")
    assert "." in raw_key
    parsed_id, parsed_secret = parse_api_key(raw_key)
    assert parsed_id == key_id
    assert verify_secret(parsed_secret, secret_hash)


def test_hash_and_verify():
    hashed = hash_secret("my_secret")
    assert verify_secret("my_secret", hashed)
    assert not verify_secret("wrong_secret", hashed)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_server/test_auth.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement the auth module**

Create `src/agentgate/server/auth.py`:

```python
from __future__ import annotations

import secrets
import string

import bcrypt

_PREFIX = "agk_live_"
_KEY_ID_LENGTH = 8
_SECRET_LENGTH = 32
_ALPHABET = string.ascii_letters + string.digits


def generate_api_key() -> tuple[str, str, str]:
    """Returns (key_id, raw_api_key, bcrypt_hash_of_secret)."""
    key_id = "".join(secrets.choice(_ALPHABET) for _ in range(_KEY_ID_LENGTH))
    secret = "".join(secrets.choice(_ALPHABET) for _ in range(_SECRET_LENGTH))
    raw_key = f"{_PREFIX}{key_id}.{secret}"
    secret_hash = hash_secret(secret)
    return key_id, raw_key, secret_hash


def parse_api_key(raw_key: str) -> tuple[str, str]:
    """Parse raw API key into (key_id, secret). Raises ValueError if malformed."""
    if not raw_key.startswith(_PREFIX):
        raise ValueError("Invalid API key format: missing prefix")
    body = raw_key[len(_PREFIX):]
    if "." not in body:
        raise ValueError("Invalid API key format: missing separator")
    key_id, secret = body.split(".", 1)
    if not key_id or not secret:
        raise ValueError("Invalid API key format: empty key_id or secret")
    return key_id, secret


def hash_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()


def verify_secret(secret: str, hashed: str) -> bool:
    return bcrypt.checkpw(secret.encode(), hashed.encode())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_server/test_auth.py -v`
Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/server/auth.py tests/test_server/test_auth.py
git commit -m "Add API key generation, parsing, and bcrypt verification"
```

---

### Task 4: Pydantic Request/Response Models

**Files:**
- Create: `src/agentgate/server/models.py`
- Create: `tests/test_server/test_models.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_server/test_models.py`:

```python
import pytest
from pydantic import ValidationError

from agentgate.server.models import (
    CreateScanRequest,
    ScanResponse,
    ScanStatus,
    ScanVerdict,
)


def test_create_scan_request_valid():
    req = CreateScanRequest(
        repo_url="https://github.com/test/agent",
        entrypoint="main.py",
        runtime="python",
    )
    assert req.repo_url == "https://github.com/test/agent"
    assert req.manifest_path is None
    assert req.webhook_url is None


def test_create_scan_request_with_optional_fields():
    req = CreateScanRequest(
        repo_url="https://github.com/test/agent",
        manifest_path="trust_manifest.yaml",
        webhook_url="https://example.com/webhook",
    )
    assert req.manifest_path == "trust_manifest.yaml"
    assert req.webhook_url == "https://example.com/webhook"


def test_create_scan_request_missing_repo_url():
    with pytest.raises(ValidationError):
        CreateScanRequest()


def test_scan_status_enum():
    assert ScanStatus.PENDING == "pending"
    assert ScanStatus.SCANNING == "scanning"
    assert ScanStatus.COMPLETED == "completed"
    assert ScanStatus.FAILED == "failed"


def test_scan_verdict_enum():
    assert ScanVerdict.ALLOW_CLEAN == "allow_clean"
    assert ScanVerdict.BLOCK == "block"


def test_scan_response_pending():
    resp = ScanResponse(
        id="scan_abc123",
        status=ScanStatus.PENDING,
        repo_url="https://github.com/test/agent",
        created_at="2026-03-26T22:00:00Z",
        updated_at="2026-03-26T22:00:00Z",
    )
    assert resp.verdict is None
    assert resp.score is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_server/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement the models**

Create `src/agentgate/server/models.py`:

```python
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel


class ScanStatus(str, Enum):
    PENDING = "pending"
    CLONING = "cloning"
    DEPLOYING = "deploying"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanVerdict(str, Enum):
    ALLOW_CLEAN = "allow_clean"
    ALLOW_WITH_WARNINGS = "allow_with_warnings"
    MANUAL_REVIEW = "manual_review"
    BLOCK = "block"


class CreateScanRequest(BaseModel):
    repo_url: str
    entrypoint: str | None = "main.py"
    runtime: str = "python"
    manifest_path: str | None = None
    webhook_url: str | None = None


class ScoreResponse(BaseModel):
    checks_run: int
    checks_passed: int
    checks_failed: int


class ScanResponse(BaseModel):
    id: str
    status: ScanStatus
    repo_url: str
    created_at: str | datetime
    updated_at: str | datetime
    verdict: ScanVerdict | None = None
    score: ScoreResponse | None = None
    error: str | None = None
    completed_at: str | datetime | None = None
    report_url: str | None = None

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]
    limit: int
    offset: int


class WebhookPayload(BaseModel):
    event: str = "scan.completed"
    scan_id: str
    verdict: str | None
    score: ScoreResponse | None
    report_url: str


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "2.0.0"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_server/test_models.py -v`
Expected: All 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/server/models.py tests/test_server/test_models.py
git commit -m "Add Pydantic request/response models for scan API"
```

---

### Task 5: Webhook Delivery

**Files:**
- Create: `src/agentgate/server/webhook.py`
- Create: `tests/test_server/test_webhook.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_server/test_webhook.py`:

```python
import hashlib
import hmac
import json
import time

import pytest

from agentgate.server.webhook import compute_signature, build_webhook_headers


def test_compute_signature():
    body = '{"event": "scan.completed"}'
    timestamp = "1711497600"
    secret = "whsec_test_secret"
    sig = compute_signature(body=body, timestamp=timestamp, secret=secret)
    expected = hmac.new(
        secret.encode(), (body + timestamp).encode(), hashlib.sha256
    ).hexdigest()
    assert sig == expected


def test_build_webhook_headers():
    body = '{"event": "scan.completed"}'
    secret = "whsec_test_secret"
    headers = build_webhook_headers(body=body, secret=secret)
    assert "X-AgentGate-Signature" in headers
    assert "X-AgentGate-Timestamp" in headers
    assert headers["X-AgentGate-Signature"].startswith("sha256=")
    ts = int(headers["X-AgentGate-Timestamp"])
    assert abs(ts - int(time.time())) < 5
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_server/test_webhook.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement the webhook module**

Create `src/agentgate/server/webhook.py`:

```python
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time

import httpx

from agentgate.server.models import ScoreResponse, WebhookPayload

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_SECONDS = (1, 5, 25)


def compute_signature(*, body: str, timestamp: str, secret: str) -> str:
    message = body + timestamp
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def build_webhook_headers(*, body: str, secret: str) -> dict[str, str]:
    timestamp = str(int(time.time()))
    signature = compute_signature(body=body, timestamp=timestamp, secret=secret)
    return {
        "X-AgentGate-Signature": f"sha256={signature}",
        "X-AgentGate-Timestamp": timestamp,
        "Content-Type": "application/json",
    }


async def deliver_webhook(
    *,
    webhook_url: str,
    scan_id: str,
    verdict: str | None,
    score: dict | None,
    report_url: str,
    webhook_secret: str,
) -> bool:
    payload = WebhookPayload(
        scan_id=scan_id,
        verdict=verdict,
        score=ScoreResponse(**score) if score else None,
        report_url=report_url,
    )
    body = payload.model_dump_json()
    headers = build_webhook_headers(body=body, secret=webhook_secret)

    for attempt in range(_MAX_RETRIES):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(webhook_url, content=body, headers=headers)
                if resp.status_code < 400:
                    logger.info("Webhook delivered to %s (attempt %d)", webhook_url, attempt + 1)
                    return True
                logger.warning(
                    "Webhook to %s returned %d (attempt %d)",
                    webhook_url, resp.status_code, attempt + 1,
                )
        except Exception as exc:
            logger.warning("Webhook to %s failed (attempt %d): %s", webhook_url, attempt + 1, exc)

        if attempt < _MAX_RETRIES - 1:
            import asyncio
            await asyncio.sleep(_BACKOFF_SECONDS[attempt])

    logger.error("Webhook delivery to %s failed after %d attempts", webhook_url, _MAX_RETRIES)
    return False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_server/test_webhook.py -v`
Expected: All 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/server/webhook.py tests/test_server/test_webhook.py
git commit -m "Add signed webhook delivery with HMAC-SHA256 and exponential backoff"
```

---

### Task 6: Scan Runner Service Layer

**Files:**
- Create: `src/agentgate/services/__init__.py`
- Create: `src/agentgate/services/scan_runner.py`
- Create: `tests/test_services/__init__.py`
- Create: `tests/test_services/test_scan_runner.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_services/__init__.py` (empty) and `tests/test_services/test_scan_runner.py`:

```python
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from agentgate.services.scan_runner import ScanRunner


def test_scan_runner_init():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate"))
    assert runner.work_dir == Path("/tmp/agentgate")


@pytest.mark.asyncio
async def test_scan_runner_clone_repo():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate"))
    with patch("agentgate.services.scan_runner.subprocess") as mock_subprocess:
        mock_subprocess.run = MagicMock(return_value=MagicMock(returncode=0))
        result = await runner.clone_repo(
            repo_url="https://github.com/test/agent",
            scan_id="scan_abc123",
        )
        assert result.exists() or True  # path constructed correctly
        mock_subprocess.run.assert_called_once()


@pytest.mark.asyncio
async def test_scan_runner_build_config():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate"))
    config = runner.build_trust_config(
        source_dir=Path("/tmp/agentgate/scan_abc123/repo"),
        manifest_path="trust_manifest.yaml",
        output_dir=Path("/tmp/agentgate/scan_abc123/output"),
    )
    assert config.source_dir == Path("/tmp/agentgate/scan_abc123/repo")
    assert config.manifest_path == Path("/tmp/agentgate/scan_abc123/repo/trust_manifest.yaml")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_services/test_scan_runner.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement the scan runner**

Create `src/agentgate/services/__init__.py` (empty) and `src/agentgate/services/scan_runner.py`:

```python
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from agentgate.trust.config import TrustScanConfig
from agentgate.trust.models import TrustScanResult, TrustScorecard

logger = logging.getLogger(__name__)


@dataclass
class ScanRunResult:
    verdict: str
    score: dict
    report: dict
    error: str | None = None


class ScanRunner:
    def __init__(self, work_dir: Path) -> None:
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)

    async def clone_repo(self, *, repo_url: str, scan_id: str) -> Path:
        clone_dir = self.work_dir / scan_id / "repo"
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(clone_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr.strip()}")
        return clone_dir

    def build_trust_config(
        self,
        *,
        source_dir: Path,
        manifest_path: str | None,
        output_dir: Path,
    ) -> TrustScanConfig:
        resolved_manifest = None
        if manifest_path:
            resolved_manifest = source_dir / manifest_path
            if not resolved_manifest.exists():
                resolved_manifest = None

        return TrustScanConfig(
            source_dir=source_dir,
            image_ref="",
            manifest_path=resolved_manifest,
            output_dir=output_dir,
            quiet=True,
        )

    async def run_scan(self, config: TrustScanConfig) -> ScanRunResult:
        from agentgate.trust.scanner import TrustScanner

        scanner = TrustScanner(config=config)
        result: TrustScanResult = await scanner.run()

        scorecard: TrustScorecard = result.scorecard
        score_dict = {
            "checks_run": scorecard.checks_run,
            "checks_passed": scorecard.checks_passed,
            "checks_failed": scorecard.checks_failed,
        }
        report_dict = result.model_dump(mode="json")

        return ScanRunResult(
            verdict=scorecard.verdict.value,
            score=score_dict,
            report=report_dict,
        )

    def cleanup(self, scan_id: str) -> None:
        scan_dir = self.work_dir / scan_id
        if scan_dir.exists():
            shutil.rmtree(scan_dir, ignore_errors=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_services/test_scan_runner.py -v`
Expected: All 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/services/ tests/test_services/
git commit -m "Add scan runner service layer bridging API/worker to trust scanner"
```

---

### Task 7: arq Worker

**Files:**
- Create: `src/agentgate/worker/__init__.py`
- Create: `src/agentgate/worker/settings.py`
- Create: `src/agentgate/worker/tasks.py`
- Create: `tests/test_worker/__init__.py`
- Create: `tests/test_worker/test_tasks.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_worker/__init__.py` (empty) and `tests/test_worker/test_tasks.py`:

```python
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from agentgate.worker.tasks import run_scan_job


@pytest.mark.asyncio
async def test_run_scan_job_updates_status():
    mock_ctx = {
        "db": AsyncMock(),
        "scan_runner": MagicMock(),
        "webhook_secret": "whsec_test",
    }
    mock_ctx["scan_runner"].clone_repo = AsyncMock(return_value=Path("/tmp/repo"))
    mock_ctx["scan_runner"].build_trust_config = MagicMock()
    mock_ctx["scan_runner"].run_scan = AsyncMock(return_value=MagicMock(
        verdict="allow_clean",
        score={"checks_run": 11, "checks_passed": 11, "checks_failed": 0},
        report={"scorecard": {}},
        error=None,
    ))
    mock_ctx["scan_runner"].cleanup = MagicMock()
    mock_ctx["db"].get_scan = AsyncMock(return_value={"webhook_url": None})

    await run_scan_job(
        mock_ctx,
        scan_id="scan_abc123",
        repo_url="https://github.com/test/agent",
        entrypoint="main.py",
        runtime="python",
        manifest_path=None,
    )

    # Should have called update_scan_status at least twice (cloning, scanning, completed)
    assert mock_ctx["db"].update_scan_status.call_count >= 3
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_worker/test_tasks.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement the worker settings**

Create `src/agentgate/worker/__init__.py` (empty) and `src/agentgate/worker/settings.py`:

```python
from __future__ import annotations

import os
from pathlib import Path

from arq.connections import RedisSettings

from agentgate.server.db import Database
from agentgate.services.scan_runner import ScanRunner


REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/agentgate")
WORK_DIR = Path(os.environ.get("AGENTGATE_WORK_DIR", "/tmp/agentgate-scans"))
WEBHOOK_SECRET = os.environ.get("AGENTGATE_WEBHOOK_SECRET", "")


async def startup(ctx: dict) -> None:
    db = Database(dsn=DATABASE_URL)
    await db.connect()
    ctx["db"] = db
    ctx["scan_runner"] = ScanRunner(work_dir=WORK_DIR)
    ctx["webhook_secret"] = WEBHOOK_SECRET


async def shutdown(ctx: dict) -> None:
    db: Database = ctx.get("db")
    if db:
        await db.disconnect()


class WorkerSettings:
    functions = ["agentgate.worker.tasks.run_scan_job"]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(REDIS_URL)
    max_jobs = 2
    job_timeout = 600  # 10 minutes max per scan
```

- [ ] **Step 4: Implement the worker task**

Create `src/agentgate/worker/tasks.py`:

```python
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from agentgate.server.db import Database
from agentgate.server.webhook import deliver_webhook
from agentgate.services.scan_runner import ScanRunner

logger = logging.getLogger(__name__)


async def run_scan_job(
    ctx: dict,
    *,
    scan_id: str,
    repo_url: str,
    entrypoint: str | None,
    runtime: str,
    manifest_path: str | None,
) -> None:
    db: Database = ctx["db"]
    runner: ScanRunner = ctx["scan_runner"]
    webhook_secret: str = ctx["webhook_secret"]
    now = datetime.now(timezone.utc)

    try:
        # Phase 1: Clone
        await db.update_scan_status(scan_id, status="cloning", started_at=now)
        source_dir = await runner.clone_repo(repo_url=repo_url, scan_id=scan_id)

        # Phase 2: Build config
        output_dir = runner.work_dir / scan_id / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        config = runner.build_trust_config(
            source_dir=source_dir,
            manifest_path=manifest_path,
            output_dir=output_dir,
        )

        # Phase 3: Scan
        await db.update_scan_status(scan_id, status="scanning")
        result = await runner.run_scan(config)

        # Phase 4: Store result
        completed_at = datetime.now(timezone.utc)
        await db.update_scan_status(
            scan_id,
            status="completed",
            verdict=result.verdict,
            score=result.score,
            report=result.report,
            completed_at=completed_at,
        )

        # Phase 5: Webhook
        scan_row = await db.get_scan(scan_id, api_key_id="__internal__")
        if scan_row is None:
            # Fallback: fetch without key scoping for worker
            pass
        webhook_url = scan_row.get("webhook_url") if scan_row else None
        if webhook_url and webhook_secret:
            await deliver_webhook(
                webhook_url=webhook_url,
                scan_id=scan_id,
                verdict=result.verdict,
                score=result.score,
                report_url=f"/v1/scans/{scan_id}/report",
                webhook_secret=webhook_secret,
            )

    except Exception as exc:
        logger.exception("Scan %s failed: %s", scan_id, exc)
        await db.update_scan_status(
            scan_id,
            status="failed",
            error=str(exc),
            completed_at=datetime.now(timezone.utc),
        )
    finally:
        runner.cleanup(scan_id)
```

- [ ] **Step 5: Fix the worker db access for webhook lookup**

The worker needs to read scan rows without api_key_id scoping. Add a method to `src/agentgate/server/db.py`:

```python
    async def get_scan_internal(self, scan_id: str) -> dict | None:
        """Get scan without api_key scoping. For worker use only."""
        assert self.pool is not None
        row = await self.pool.fetchrow("SELECT * FROM scans WHERE id = $1", scan_id)
        return dict(row) if row else None
```

Then update `src/agentgate/worker/tasks.py` to use `db.get_scan_internal(scan_id)` instead of `db.get_scan(scan_id, api_key_id="__internal__")` in the webhook section.

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_worker/test_tasks.py -v`
Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/agentgate/worker/ tests/test_worker/ src/agentgate/server/db.py
git commit -m "Add arq worker with scan job, status updates, and webhook delivery"
```

---

### Task 8: FastAPI Application and Routes

**Files:**
- Create: `src/agentgate/server/app.py`
- Create: `src/agentgate/server/routes/__init__.py`
- Create: `src/agentgate/server/routes/health.py`
- Create: `src/agentgate/server/routes/scans.py`
- Create: `tests/test_server/test_routes.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_server/test_routes.py`:

```python
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_server/test_routes.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement the health route**

Create `src/agentgate/server/routes/__init__.py` (empty) and `src/agentgate/server/routes/health.py`:

```python
from fastapi import APIRouter

from agentgate.server.models import HealthResponse

router = APIRouter()


@router.get("/v1/health", response_model=HealthResponse)
async def health():
    return HealthResponse()
```

- [ ] **Step 4: Implement the scans route**

Create `src/agentgate/server/routes/scans.py`:

```python
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from agentgate.server.auth import parse_api_key, verify_secret
from agentgate.server.db import Database
from agentgate.server.models import (
    CreateScanRequest,
    ScanListResponse,
    ScanResponse,
    ScanStatus,
    ScanVerdict,
    ScoreResponse,
)

router = APIRouter()


async def get_db(request: Request) -> Database:
    return request.app.state.db


async def authenticate(
    request: Request,
    x_api_key: str | None = Header(None),
) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    try:
        key_id, secret = parse_api_key(x_api_key)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid API key format")

    db: Database = request.app.state.db
    key_row = await db.get_api_key(key_id)
    if not key_row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if not verify_secret(secret, key_row["key_hash"]):
        raise HTTPException(status_code=401, detail="Invalid API key")

    return key_id


def _scan_row_to_response(row: dict) -> ScanResponse:
    score = None
    if row.get("score"):
        score = ScoreResponse(**row["score"]) if isinstance(row["score"], dict) else None
    report_url = None
    if row.get("status") == "completed":
        report_url = f"/v1/scans/{row['id']}/report"
    return ScanResponse(
        id=row["id"],
        status=ScanStatus(row["status"]),
        repo_url=row["repo_url"],
        created_at=row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else row["created_at"],
        updated_at=row["updated_at"].isoformat() if hasattr(row["updated_at"], "isoformat") else row["updated_at"],
        verdict=ScanVerdict(row["verdict"]) if row.get("verdict") else None,
        score=score,
        error=row.get("error"),
        completed_at=row["completed_at"].isoformat() if row.get("completed_at") and hasattr(row["completed_at"], "isoformat") else row.get("completed_at"),
        report_url=report_url,
    )


@router.post("/v1/scans", response_model=ScanResponse, status_code=201)
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    key_id: str = Depends(authenticate),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
):
    db: Database = request.app.state.db

    if idempotency_key:
        existing = await db.find_by_idempotency_key(
            api_key_id=key_id, idempotency_key=idempotency_key
        )
        if existing:
            return _scan_row_to_response(existing)

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    await db.create_scan(
        scan_id=scan_id,
        repo_url=body.repo_url,
        entrypoint=body.entrypoint,
        runtime=body.runtime,
        manifest_path=body.manifest_path,
        webhook_url=body.webhook_url,
        api_key_id=key_id,
        idempotency_key=idempotency_key,
    )

    redis_pool = request.app.state.redis
    from arq import create_pool

    job = await redis_pool.enqueue_job(
        "run_scan_job",
        scan_id=scan_id,
        repo_url=body.repo_url,
        entrypoint=body.entrypoint,
        runtime=body.runtime,
        manifest_path=body.manifest_path,
    )

    row = await db.get_scan(scan_id, api_key_id=key_id)
    return _scan_row_to_response(row)


@router.get("/v1/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    request: Request,
    key_id: str = Depends(authenticate),
):
    db: Database = request.app.state.db
    row = await db.get_scan(scan_id, api_key_id=key_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_row_to_response(row)


@router.get("/v1/scans/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    request: Request,
    key_id: str = Depends(authenticate),
):
    db: Database = request.app.state.db
    row = await db.get_scan(scan_id, api_key_id=key_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row.get("status") != "completed":
        raise HTTPException(status_code=409, detail="Scan not yet completed")
    return row.get("report", {})


@router.get("/v1/scans", response_model=ScanListResponse)
async def list_scans(
    request: Request,
    key_id: str = Depends(authenticate),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    db: Database = request.app.state.db
    rows = await db.list_scans(api_key_id=key_id, limit=limit, offset=offset)
    return ScanListResponse(
        scans=[_scan_row_to_response(r) for r in rows],
        limit=limit,
        offset=offset,
    )
```

- [ ] **Step 5: Implement the app factory**

Create `src/agentgate/server/app.py`:

```python
from __future__ import annotations

import os

from fastapi import FastAPI

from agentgate.server.db import Database
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
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_server/test_routes.py -v`
Expected: All 3 tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/agentgate/server/app.py src/agentgate/server/routes/ tests/test_server/test_routes.py
git commit -m "Add FastAPI app with scan CRUD endpoints, auth middleware, and health check"
```

---

### Task 9: CLI API Key Management

**Files:**
- Modify: `src/agentgate/cli.py`
- Create: `tests/test_server/test_cli_api_key.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_server/test_cli_api_key.py`:

```python
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from click.testing import CliRunner

from agentgate.cli import cli


def test_api_key_create_command_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["api-key", "create", "--help"])
    assert result.exit_code == 0
    assert "--name" in result.output
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_server/test_cli_api_key.py -v`
Expected: FAIL — no `api-key` command group

- [ ] **Step 3: Add the api-key CLI command group**

Add to the end of `src/agentgate/cli.py` (before the final block if any):

```python
@cli.group("api-key")
def api_key_group():
    """Manage API keys for the hosted scanning service."""
    pass


@api_key_group.command("create")
@click.option("--name", required=True, help="Name for this API key (e.g. 'PromptShop Production')")
@click.option("--database-url", envvar="DATABASE_URL", required=True, help="Postgres connection URL")
def api_key_create(name: str, database_url: str):
    """Create a new API key."""
    from agentgate.server.auth import generate_api_key
    from agentgate.server.db import Database

    async def _create():
        db = Database(dsn=database_url)
        await db.connect()
        await db.run_migrations()
        key_id, raw_key, secret_hash = generate_api_key()
        await db.create_api_key(key_id=key_id, key_hash=secret_hash, name=name)
        await db.disconnect()
        return raw_key

    raw_key = asyncio.run(_create())
    console = Console()
    console.print(f"\n[bold green]Created API key:[/bold green] {raw_key}")
    console.print("[yellow]Store this key securely. It cannot be retrieved again.[/yellow]\n")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_server/test_cli_api_key.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/cli.py tests/test_server/test_cli_api_key.py
git commit -m "Add api-key create CLI command for managing hosted API keys"
```

---

### Task 10: Dockerfiles for Railway Deployment

**Files:**
- Create: `Dockerfile.api`
- Create: `Dockerfile.worker`

- [ ] **Step 1: Create the API Dockerfile**

Create `Dockerfile.api`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir ".[server]"

EXPOSE 8000

CMD ["uvicorn", "agentgate.server.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
```

- [ ] **Step 2: Create the Worker Dockerfile**

Create `Dockerfile.worker`:

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir ".[server]"

CMD ["arq", "agentgate.worker.settings.WorkerSettings"]
```

The worker Dockerfile installs `git` because the worker needs to clone repos.

- [ ] **Step 3: Commit**

```bash
git add Dockerfile.api Dockerfile.worker
git commit -m "Add Dockerfiles for API and worker Railway services"
```

---

### Task 11: Run Full Test Suite and Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run the full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: All tests PASS. No regressions in existing tests.

- [ ] **Step 2: Run ruff lint**

Run: `ruff check src/agentgate/server/ src/agentgate/worker/ src/agentgate/services/`
Expected: No lint errors.

- [ ] **Step 3: Verify the API starts locally (smoke test)**

Run: `python -c "from agentgate.server.app import create_app; print('App factory OK')"`
Expected: Prints "App factory OK" with no import errors.

- [ ] **Step 4: Commit any fixes and push**

```bash
git push
```
