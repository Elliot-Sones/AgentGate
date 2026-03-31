# Production Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the hosted API production-ready with structured failure taxonomy, API hardening, and static auth detection metadata.

**Architecture:** Three independent workstreams: (1) enrich ProbeError with factual HTTP observations, add runner-level failure classification; (2) harden the FastAPI server with lifespan, error envelope, input validation, health check, rate limiting, CORS; (3) detect auth patterns in source code as operational metadata on GeneratedRuntimeProfile.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic, slowapi, asyncpg, arq, httpx

**Spec:** `docs/superpowers/specs/2026-03-30-production-hardening-design.md`

---

### Task 1: Enrich ProbeError with structured fields

**Files:**
- Modify: `src/agentgate/scanner.py:41-42`
- Test: `tests/test_integration/test_scanner.py`

- [ ] **Step 1: Write the failing test**

Create test in `tests/test_integration/test_scanner.py`:

```python
def test_probe_error_carries_structured_fields():
    from agentgate.scanner import ProbeError

    exc = ProbeError(
        "Agent returned HTTP 401: Unauthorized",
        status_code=401,
        target_url="https://example.com/chat",
        response_excerpt='{"error": "unauthorized"}',
        headers={"WWW-Authenticate": "Bearer"},
    )
    assert str(exc) == "Agent returned HTTP 401: Unauthorized"
    assert exc.status_code == 401
    assert exc.target_url == "https://example.com/chat"
    assert exc.response_excerpt == '{"error": "unauthorized"}'
    assert exc.headers == {"WWW-Authenticate": "Bearer"}


def test_probe_error_defaults_are_backward_compatible():
    from agentgate.scanner import ProbeError

    exc = ProbeError("simple message")
    assert str(exc) == "simple message"
    assert exc.status_code is None
    assert exc.target_url == ""
    assert exc.response_excerpt == ""
    assert exc.headers == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_integration/test_scanner.py::test_probe_error_carries_structured_fields tests/test_integration/test_scanner.py::test_probe_error_defaults_are_backward_compatible -v`
Expected: FAIL — `ProbeError.__init__` doesn't accept keyword arguments

- [ ] **Step 3: Implement ProbeError enrichment**

In `src/agentgate/scanner.py`, replace lines 41-42:

```python
class ProbeError(Exception):
    """Raised when the initial probe of the target agent fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        target_url: str = "",
        response_excerpt: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.target_url = target_url
        self.response_excerpt = response_excerpt
        self.headers = headers or {}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_integration/test_scanner.py::test_probe_error_carries_structured_fields tests/test_integration/test_scanner.py::test_probe_error_defaults_are_backward_compatible -v`
Expected: PASS

- [ ] **Step 5: Run full test suite to confirm backward compatibility**

Run: `uv run pytest tests/ -x -q`
Expected: All tests pass — existing `ProbeError("message")` callers are unaffected

- [ ] **Step 6: Commit**

```bash
git add src/agentgate/scanner.py tests/test_integration/test_scanner.py
git commit -m "Enrich ProbeError with structured HTTP observation fields"
```

---

### Task 2: Wire structured facts into _await_live_attack_readiness

**Files:**
- Modify: `src/agentgate/services/scan_runner.py:850-874`
- Test: `tests/test_services/test_scan_runner.py`

- [ ] **Step 1: Write the failing test**

Add tests to `tests/test_services/test_scan_runner.py`:

```python
@pytest.mark.asyncio
async def test_await_live_attack_readiness_raises_structured_probe_error_on_401():
    from agentgate.scanner import ProbeError
    from agentgate.adapters.base import AdapterResponse

    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    mock_adapter = AsyncMock()
    mock_adapter.send = AsyncMock(return_value=AdapterResponse(
        text="Unauthorized",
        status_code=401,
        error=None,
        raw_response=None,
    ))
    mock_adapter.close = AsyncMock()

    with patch("agentgate.services.scan_runner.HTTPAdapter", return_value=mock_adapter):
        with pytest.raises(ProbeError) as exc_info:
            await runner._await_live_attack_readiness(
                agent_config=AgentConfig(
                    url="https://example.com/chat",
                    name="test",
                ),
                timeout_seconds=0.1,
                poll_seconds=0.05,
            )
        assert exc_info.value.status_code == 401
        assert exc_info.value.target_url == "https://example.com/chat"
        assert "Unauthorized" in exc_info.value.response_excerpt


@pytest.mark.asyncio
async def test_await_live_attack_readiness_raises_none_status_on_connection_error():
    from agentgate.scanner import ProbeError
    from agentgate.adapters.base import AdapterResponse

    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    mock_adapter = AsyncMock()
    mock_adapter.send = AsyncMock(return_value=AdapterResponse(
        text="",
        status_code=0,
        error="Connection refused",
        raw_response=None,
    ))
    mock_adapter.close = AsyncMock()

    with patch("agentgate.services.scan_runner.HTTPAdapter", return_value=mock_adapter):
        with pytest.raises(ProbeError) as exc_info:
            await runner._await_live_attack_readiness(
                agent_config=AgentConfig(
                    url="https://example.com/chat",
                    name="test",
                ),
                timeout_seconds=0.1,
                poll_seconds=0.05,
            )
        assert exc_info.value.status_code is None
        assert exc_info.value.target_url == "https://example.com/chat"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_services/test_scan_runner.py::test_await_live_attack_readiness_raises_structured_probe_error_on_401 tests/test_services/test_scan_runner.py::test_await_live_attack_readiness_raises_none_status_on_connection_error -v`
Expected: FAIL — ProbeError is raised but without `status_code` field set

- [ ] **Step 3: Implement structured ProbeError in _await_live_attack_readiness**

In `src/agentgate/services/scan_runner.py`, replace `_await_live_attack_readiness` (lines 850-874):

```python
async def _await_live_attack_readiness(
    self,
    *,
    agent_config: AgentConfig,
    timeout_seconds: float = 60.0,
    poll_seconds: float = 3.0,
) -> None:
    adapter = HTTPAdapter(agent_config, timeout=30.0, max_retries=1)
    deadline = time.monotonic() + timeout_seconds
    last_error = "Agent never became usable enough for the mandatory live attack scan."
    last_status_code: int | None = None
    last_body: str = ""
    last_reachable: bool = False
    try:
        while time.monotonic() < deadline:
            response = await adapter.send("hello")
            if not response.error and response.status_code < 400 and response.text.strip():
                return
            if response.error:
                last_error = f"Agent returned error: {response.error}"
                last_status_code = None
                last_body = ""
            elif response.status_code >= 400:
                last_error = f"Agent returned HTTP {response.status_code}: {response.text[:200]}"
                last_status_code = response.status_code
                last_body = response.text[:500] if response.text else ""
                last_reachable = True
            else:
                last_error = "Agent returned an empty response"
                last_status_code = response.status_code
                last_body = ""
                last_reachable = True
            await asyncio.sleep(poll_seconds)
    finally:
        await adapter.close()
    raise ProbeError(
        last_error,
        status_code=last_status_code,
        target_url=agent_config.url,
        response_excerpt=last_body,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_services/test_scan_runner.py::test_await_live_attack_readiness_raises_structured_probe_error_on_401 tests/test_services/test_scan_runner.py::test_await_live_attack_readiness_raises_none_status_on_connection_error -v`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest tests/ -x -q`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/agentgate/services/scan_runner.py tests/test_services/test_scan_runner.py
git commit -m "Capture structured HTTP facts in ProbeError from readiness poll"
```

---

### Task 3: Add _classify_probe_failure and wire into _run_live_attack_scan

**Files:**
- Modify: `src/agentgate/services/scan_runner.py:490-515` (ProbeError catch block)
- Test: `tests/test_services/test_scan_runner.py`

- [ ] **Step 1: Write the failing tests**

Add tests to `tests/test_services/test_scan_runner.py`:

```python
def test_classify_probe_failure_401_is_auth_required():
    from agentgate.scanner import ProbeError

    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    exc = ProbeError("HTTP 401", status_code=401, target_url="https://x.com/chat")
    assert runner._classify_probe_failure(exc) == "auth_required"


def test_classify_probe_failure_403_is_auth_required():
    from agentgate.scanner import ProbeError

    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    exc = ProbeError("HTTP 403", status_code=403, target_url="https://x.com/chat")
    assert runner._classify_probe_failure(exc) == "auth_required"


def test_classify_probe_failure_404_is_endpoint_not_found():
    from agentgate.scanner import ProbeError

    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    exc = ProbeError("HTTP 404", status_code=404, target_url="https://x.com/chat")
    assert runner._classify_probe_failure(exc) == "endpoint_not_found"


def test_classify_probe_failure_500_is_deployment_unusable():
    from agentgate.scanner import ProbeError

    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    exc = ProbeError("HTTP 500", status_code=500, target_url="https://x.com/chat")
    assert runner._classify_probe_failure(exc) == "deployment_unusable"


def test_classify_probe_failure_502_is_deployment_unusable():
    from agentgate.scanner import ProbeError

    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    exc = ProbeError("HTTP 502", status_code=502, target_url="https://x.com/chat")
    assert runner._classify_probe_failure(exc) == "deployment_unusable"


def test_classify_probe_failure_none_status_is_boot_timeout():
    from agentgate.scanner import ProbeError

    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    exc = ProbeError("Connection refused", status_code=None, target_url="https://x.com/chat")
    assert runner._classify_probe_failure(exc) == "boot_timeout"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_services/test_scan_runner.py -k "test_classify_probe_failure" -v`
Expected: FAIL — `_classify_probe_failure` method does not exist

- [ ] **Step 3: Implement _classify_probe_failure**

Add to the `ScanRunner` class in `src/agentgate/services/scan_runner.py` (after `_await_live_attack_readiness`):

```python
@staticmethod
def _classify_probe_failure(exc: ProbeError) -> str:
    if exc.status_code in (401, 403):
        return "auth_required"
    if exc.status_code == 404:
        return "endpoint_not_found"
    if exc.status_code is not None and exc.status_code >= 500:
        return "deployment_unusable"
    return "boot_timeout"
```

- [ ] **Step 4: Run classification tests**

Run: `uv run pytest tests/test_services/test_scan_runner.py -k "test_classify_probe_failure" -v`
Expected: All 6 PASS

- [ ] **Step 5: Wire _classify_probe_failure into the ProbeError catch block**

In `src/agentgate/services/scan_runner.py`, replace the `except ProbeError as exc:` block (lines 490-515):

```python
except ProbeError as exc:
    error = str(exc).strip() or "Agent never became usable enough for the mandatory live attack scan."
    failure_reason = self._classify_probe_failure(exc)
    report_payload = {
        "phase": "live_attack_scan",
        "status": "failed",
        "detail": error,
        "target_url": target_url,
        "request_field": request_field,
        "response_field": response_field,
        "attack_hints": attack_hints,
        "failure_reason": failure_reason,
    }
    if failure_reason == "boot_timeout":
        report_payload["reachable_before_timeout"] = getattr(exc, "status_code", None) is not None
    await self._emit_event(
        event_callback,
        status="failed",
        phase="live_attack_scan_failed",
        detail=error,
        event_type="scan.failed",
        payload={"target_url": target_url, "failure_reason": failure_reason},
    )
    return {
        "phase": "live_attack_scan",
        "status": "failed",
        "usable": False,
        "error": error,
        "failure_reason": failure_reason,
        "report": report_payload,
    }
```

- [ ] **Step 6: Run full test suite**

Run: `uv run pytest tests/ -x -q`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add src/agentgate/services/scan_runner.py tests/test_services/test_scan_runner.py
git commit -m "Add typed probe failure classification in scan runner"
```

---

### Task 4: FastAPI lifespan migration

**Files:**
- Modify: `src/agentgate/server/app.py`
- Modify: `tests/test_server/test_routes.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_server/test_routes.py`:

```python
@pytest.mark.asyncio
async def test_lifespan_skips_injected_resources(app, mock_db, mock_redis):
    """Lifespan must not recreate or close resources injected before startup."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/v1/health")
        assert resp.status_code == 200
    # The mock_db and mock_redis should NOT have disconnect/close called by lifespan
    # because they were injected externally. The test fixture sets them before startup.
    mock_db.disconnect.assert_not_called()
    mock_redis.close.assert_not_called()
```

- [ ] **Step 2: Run test to verify current state**

Run: `uv run pytest tests/test_server/test_routes.py::test_lifespan_skips_injected_resources -v`
Expected: May pass or fail depending on how the existing on_event handlers behave with injected state — establishes baseline

- [ ] **Step 3: Implement lifespan migration**

Replace the entire `create_app()` function in `src/agentgate/server/app.py`:

```python
from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from agentgate.server.routes.health import router as health_router
from agentgate.server.routes.scans import router as scans_router
from agentgate.server.urls import resolve_public_base_url


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

    return app
```

- [ ] **Step 4: Run the lifespan test and the full route test suite**

Run: `uv run pytest tests/test_server/test_routes.py -v`
Expected: All pass, no deprecation warnings about `on_event`

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/server/app.py tests/test_server/test_routes.py
git commit -m "Migrate FastAPI lifecycle to lifespan context manager"
```

---

### Task 5: Error envelope

**Files:**
- Modify: `src/agentgate/server/app.py`
- Test: `tests/test_server/test_routes.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_server/test_routes.py`:

```python
@pytest.mark.asyncio
async def test_error_envelope_validation_error(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/scans",
            json={},
            headers={"X-API-Key": "agk_live_testkey1.testsecret"},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["error"] == "validation_error"
        assert "detail" in data


@pytest.mark.asyncio
async def test_error_envelope_unauthorized(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/v1/scans", json={"repo_url": "https://github.com/t/a"})
        assert resp.status_code == 401
        data = resp.json()
        assert data["error"] == "unauthorized"
        assert "detail" in data


@pytest.mark.asyncio
async def test_error_envelope_not_found(app, mock_db):
    mock_db.get_scan = AsyncMock(return_value=None)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("agentgate.server.auth.verify_secret", return_value=True):
            resp = await client.get(
                "/v1/scans/scan_nonexistent",
                headers={"X-API-Key": "agk_live_testkey1.testsecret"},
            )
        assert resp.status_code == 404
        data = resp.json()
        assert data["error"] == "not_found"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_server/test_routes.py::test_error_envelope_validation_error tests/test_server/test_routes.py::test_error_envelope_unauthorized tests/test_server/test_routes.py::test_error_envelope_not_found -v`
Expected: FAIL — responses don't have `"error"` key in the expected format

- [ ] **Step 3: Implement error envelope handlers**

Add to `src/agentgate/server/app.py`, inside `create_app()` after router registration:

```python
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

_HTTP_ERROR_CODES: dict[int, str] = {
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    429: "rate_limited",
    503: "service_unavailable",
}

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc: RequestValidationError):
    details = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error.get("loc", []) if loc != "body")
        details.append(f"{field}: {error['msg']}" if field else error["msg"])
    return JSONResponse(
        status_code=422,
        content={"error": "validation_error", "detail": "; ".join(details)},
    )

@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request, exc: StarletteHTTPException):
    code = _HTTP_ERROR_CODES.get(exc.status_code, "api_error")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": code, "detail": str(exc.detail)},
    )

@app.exception_handler(Exception)
async def catch_all_handler(request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "detail": "An unexpected error occurred."},
    )
```

- [ ] **Step 4: Run envelope tests**

Run: `uv run pytest tests/test_server/test_routes.py::test_error_envelope_validation_error tests/test_server/test_routes.py::test_error_envelope_unauthorized tests/test_server/test_routes.py::test_error_envelope_not_found -v`
Expected: PASS

- [ ] **Step 5: Run full route test suite to ensure existing tests still pass**

Run: `uv run pytest tests/test_server/test_routes.py -v`
Expected: All pass. Note: existing tests that check `resp.status_code == 401` still pass — the status codes don't change, only the response body shape does.

- [ ] **Step 6: Commit**

```bash
git add src/agentgate/server/app.py tests/test_server/test_routes.py
git commit -m "Add consistent error envelope with semantic error codes"
```

---

### Task 6: Input validation — _is_private_host utility and repo_url/webhook_url/runtime validators

**Files:**
- Modify: `src/agentgate/server/models.py`
- Modify: `tests/test_server/test_models.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_server/test_models.py`:

```python
def test_create_scan_request_rejects_http_repo_url():
    with pytest.raises(ValidationError, match="repo_url"):
        CreateScanRequest(repo_url="http://github.com/test/agent")


def test_create_scan_request_rejects_localhost_repo_url():
    with pytest.raises(ValidationError, match="repo_url"):
        CreateScanRequest(repo_url="https://localhost/test/agent")


def test_create_scan_request_rejects_private_ip_repo_url():
    with pytest.raises(ValidationError, match="repo_url"):
        CreateScanRequest(repo_url="https://10.0.0.1/test/agent")


def test_create_scan_request_rejects_link_local_repo_url():
    with pytest.raises(ValidationError, match="repo_url"):
        CreateScanRequest(repo_url="https://169.254.1.1/test/agent")


def test_create_scan_request_accepts_github_tree_url():
    req = CreateScanRequest(
        repo_url="https://github.com/test/agent/tree/feature/branch",
    )
    assert req.repo_url == "https://github.com/test/agent/tree/feature/branch"


def test_create_scan_request_accepts_gitlab_url():
    req = CreateScanRequest(repo_url="https://gitlab.com/test/agent")
    assert req.repo_url == "https://gitlab.com/test/agent"


def test_create_scan_request_rejects_empty_repo_url():
    with pytest.raises(ValidationError, match="repo_url"):
        CreateScanRequest(repo_url="")


def test_create_scan_request_rejects_non_url_repo_url():
    with pytest.raises(ValidationError, match="repo_url"):
        CreateScanRequest(repo_url="not-a-url")


def test_create_scan_request_rejects_http_webhook_url():
    with pytest.raises(ValidationError, match="webhook_url"):
        CreateScanRequest(
            repo_url="https://github.com/test/agent",
            webhook_url="http://example.com/hook",
        )


def test_create_scan_request_rejects_private_webhook_url():
    with pytest.raises(ValidationError, match="webhook_url"):
        CreateScanRequest(
            repo_url="https://github.com/test/agent",
            webhook_url="https://192.168.1.1/hook",
        )


def test_create_scan_request_accepts_https_webhook_url():
    req = CreateScanRequest(
        repo_url="https://github.com/test/agent",
        webhook_url="https://api.promptshop.co/webhooks/agentgate",
    )
    assert req.webhook_url == "https://api.promptshop.co/webhooks/agentgate"


def test_create_scan_request_allows_localhost_webhook_in_dev_mode():
    import os
    os.environ["AGENTGATE_DEV_MODE"] = "1"
    try:
        req = CreateScanRequest(
            repo_url="https://github.com/test/agent",
            webhook_url="http://localhost:3000/hook",
        )
        assert req.webhook_url == "http://localhost:3000/hook"
    finally:
        del os.environ["AGENTGATE_DEV_MODE"]


def test_create_scan_request_rejects_invalid_runtime():
    with pytest.raises(ValidationError, match="runtime"):
        CreateScanRequest(
            repo_url="https://github.com/test/agent",
            runtime="node",
        )


def test_create_scan_request_accepts_python_runtime():
    req = CreateScanRequest(
        repo_url="https://github.com/test/agent",
        runtime="python",
    )
    assert req.runtime == "python"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_server/test_models.py -k "rejects_http_repo_url or rejects_localhost or rejects_private_ip or rejects_invalid_runtime" -v`
Expected: FAIL — no validation on these fields yet

- [ ] **Step 3: Implement validators**

In `src/agentgate/server/models.py`, add imports and the private-host utility at the top:

```python
from __future__ import annotations

import ipaddress
import os
from datetime import datetime
from enum import Enum
from pathlib import PurePosixPath
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator


def _is_private_host(hostname: str) -> bool:
    """Check if a hostname is private, loopback, or link-local (syntactic check only)."""
    hostname = hostname.strip("[]").lower()
    if hostname in ("localhost", ""):
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        pass
    # Check for common private DNS patterns
    if hostname.endswith(".local") or hostname.endswith(".internal"):
        return True
    return False
```

Then update `CreateScanRequest`:

```python
class CreateScanRequest(BaseModel):
    repo_url: str
    git_ref: str | None = None
    entrypoint: str | None = "main.py"
    runtime: Literal["python"] = "python"
    manifest_path: str | None = None
    dockerfile_path: str | None = None
    webhook_url: str | None = None

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("repo_url must not be empty")
        parsed = urlparse(value.strip())
        if parsed.scheme != "https":
            raise ValueError("repo_url must use https://")
        if not parsed.hostname:
            raise ValueError("repo_url must include a hostname")
        if _is_private_host(parsed.hostname):
            raise ValueError("repo_url must not target a private or internal host")
        return value.strip()

    @field_validator("webhook_url")
    @classmethod
    def validate_webhook_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        parsed = urlparse(value)
        dev_mode = os.environ.get("AGENTGATE_DEV_MODE", "") == "1"
        if dev_mode and parsed.hostname in ("localhost", "127.0.0.1", "::1"):
            return value
        if parsed.scheme != "https":
            raise ValueError("webhook_url must use https://")
        if not parsed.hostname:
            raise ValueError("webhook_url must include a hostname")
        if _is_private_host(parsed.hostname):
            raise ValueError("webhook_url must not target a private or internal host")
        return value

    @field_validator("manifest_path", "dockerfile_path")
    @classmethod
    def validate_repo_relative_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        path = PurePosixPath(normalized)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Path must stay within the repository root")
        return normalized

    @field_validator("git_ref")
    @classmethod
    def validate_git_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None
```

- [ ] **Step 4: Run validation tests**

Run: `uv run pytest tests/test_server/test_models.py -v`
Expected: All pass (new and existing)

- [ ] **Step 5: Run full route tests to check integration**

Run: `uv run pytest tests/test_server/ -v`
Expected: All pass. Note: existing route tests use `repo_url="https://github.com/test/agent"` which passes the new validator.

- [ ] **Step 6: Commit**

```bash
git add src/agentgate/server/models.py tests/test_server/test_models.py
git commit -m "Add input validation with SSRF protection for repo_url and webhook_url"
```

---

### Task 7: Webhook send-time IP resolution guard

**Files:**
- Modify: `src/agentgate/server/webhook.py`
- Test: `tests/test_server/test_webhook.py` (create if not exists, or add to existing)

- [ ] **Step 1: Check for existing webhook tests**

Run: `uv run pytest tests/test_server/ --collect-only -q 2>&1 | grep webhook`
Look for existing test file to add to.

- [ ] **Step 2: Write the failing tests**

Create or add to the webhook test file:

```python
import pytest
from unittest.mock import patch

from agentgate.server.webhook import _resolve_and_check_ip


def test_resolve_and_check_ip_rejects_loopback():
    with patch("agentgate.server.webhook.socket.getaddrinfo", return_value=[
        (2, 1, 6, "", ("127.0.0.1", 443)),
    ]):
        with pytest.raises(ValueError, match="private"):
            _resolve_and_check_ip("https://evil.example.com/hook")


def test_resolve_and_check_ip_rejects_private_range():
    with patch("agentgate.server.webhook.socket.getaddrinfo", return_value=[
        (2, 1, 6, "", ("10.0.0.5", 443)),
    ]):
        with pytest.raises(ValueError, match="private"):
            _resolve_and_check_ip("https://rebind.example.com/hook")


def test_resolve_and_check_ip_allows_public():
    with patch("agentgate.server.webhook.socket.getaddrinfo", return_value=[
        (2, 1, 6, "", ("93.184.216.34", 443)),
    ]):
        _resolve_and_check_ip("https://example.com/hook")  # Should not raise


def test_resolve_and_check_ip_rejects_link_local():
    with patch("agentgate.server.webhook.socket.getaddrinfo", return_value=[
        (2, 1, 6, "", ("169.254.1.1", 443)),
    ]):
        with pytest.raises(ValueError, match="private"):
            _resolve_and_check_ip("https://rebind.example.com/hook")
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_server/test_webhook.py -k "resolve_and_check" -v`
Expected: FAIL — `_resolve_and_check_ip` does not exist

- [ ] **Step 4: Implement _resolve_and_check_ip**

Add to `src/agentgate/server/webhook.py`, after the imports:

```python
import ipaddress
import socket
from urllib.parse import urlparse


def _resolve_and_check_ip(url: str) -> None:
    """Resolve URL hostname and reject private/loopback/link-local IPs."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        results = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")
    for family, type_, proto, canonname, sockaddr in results:
        addr = ipaddress.ip_address(sockaddr[0])
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            raise ValueError(
                f"Webhook target {hostname} resolves to private address {addr}"
            )
```

- [ ] **Step 5: Wire the check into deliver_webhook**

In `src/agentgate/server/webhook.py`, add the check at the top of `deliver_webhook()`, before the payload construction:

```python
async def deliver_webhook(
    *,
    webhook_url: str,
    # ... existing params ...
) -> bool:
    try:
        _resolve_and_check_ip(webhook_url)
    except ValueError:
        logger.warning("Webhook to %s blocked: resolves to private IP", webhook_url)
        return False

    # ... rest of existing function unchanged ...
```

- [ ] **Step 6: Run tests**

Run: `uv run pytest tests/test_server/test_webhook.py -v`
Expected: All pass

- [ ] **Step 7: Run full test suite**

Run: `uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 8: Commit**

```bash
git add src/agentgate/server/webhook.py tests/test_server/test_webhook.py
git commit -m "Add DNS-resolution SSRF guard for webhook delivery"
```

---

### Task 8: Deep health check

**Files:**
- Modify: `src/agentgate/server/routes/health.py`
- Modify: `tests/test_server/test_routes.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_server/test_routes.py`:

```python
@pytest.mark.asyncio
async def test_health_returns_503_when_db_unavailable(mock_redis):
    application = create_app()
    application.state.db = None
    application.state.redis = mock_redis
    application.state.webhook_secret = "test"
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/v1/health")
        assert resp.status_code == 503
        data = resp.json()
        assert data["error"] == "service_unavailable"


@pytest.mark.asyncio
async def test_health_returns_503_when_redis_unavailable(mock_db):
    application = create_app()
    application.state.db = mock_db
    mock_db.pool = AsyncMock()
    mock_db.pool.fetchval = AsyncMock(return_value=1)
    application.state.redis = None
    application.state.webhook_secret = "test"
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/v1/health")
        assert resp.status_code == 503


@pytest.mark.asyncio
async def test_health_returns_200_when_both_healthy(mock_db, mock_redis):
    application = create_app()
    application.state.db = mock_db
    mock_db.pool = AsyncMock()
    mock_db.pool.fetchval = AsyncMock(return_value=1)
    mock_redis.ping = AsyncMock(return_value=True)
    application.state.redis = mock_redis
    application.state.webhook_secret = "test"
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_server/test_routes.py::test_health_returns_503_when_db_unavailable -v`
Expected: FAIL — health check returns 200 regardless

- [ ] **Step 3: Implement deep health check**

Replace `src/agentgate/server/routes/health.py`:

```python
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
```

- [ ] **Step 4: Run health check tests**

Run: `uv run pytest tests/test_server/test_routes.py -k "health" -v`
Expected: All pass

- [ ] **Step 5: Fix the existing test_health_endpoint**

The original `test_health_endpoint` fixture's `mock_db` doesn't have a `pool` attribute. Update the `mock_db` fixture in `tests/test_server/test_routes.py` to include it:

```python
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
```

- [ ] **Step 6: Run full route test suite**

Run: `uv run pytest tests/test_server/test_routes.py -v`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add src/agentgate/server/routes/health.py tests/test_server/test_routes.py
git commit -m "Deep health check probes Postgres and Redis connectivity"
```

---

### Task 9: Rate limiting on POST /v1/scans

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/agentgate/server/app.py`
- Modify: `src/agentgate/server/routes/scans.py`
- Modify: `tests/test_server/test_routes.py`

- [ ] **Step 1: Add slowapi dependency**

In `pyproject.toml`, add `"slowapi>=0.1.9"` to the `server` optional-dependencies:

```toml
server = [
    "fastapi>=0.115.0",
    "uvicorn>=0.32.0",
    "arq>=0.26.0",
    "asyncpg>=0.30.0",
    "bcrypt>=4.0.0",
    "redis[hiredis]>=5.0.0",
    "slowapi>=0.1.9",
]
```

- [ ] **Step 2: Install the dependency**

Run: `uv sync --extra server --extra dev`

- [ ] **Step 3: Write the failing test**

Add to `tests/test_server/test_routes.py`:

```python
@pytest.mark.asyncio
async def test_rate_limit_returns_429_after_threshold(app, mock_db, mock_redis):
    mock_db.create_scan = AsyncMock()
    mock_db.get_scan = AsyncMock(return_value={
        "id": "scan_abc123",
        "status": "pending",
        "phase": "queued",
        "status_detail": "Scan accepted.",
        "progress_current": 0,
        "progress_total": 0,
        "repo_url": "https://github.com/test/agent",
        "git_ref": None,
        "dockerfile_path": None,
        "created_at": "2026-03-28T00:00:00Z",
        "updated_at": "2026-03-28T00:00:00Z",
        "verdict": None,
        "score": None,
        "report": None,
        "error": None,
        "completed_at": None,
    })
    mock_db.find_by_idempotency_key = AsyncMock(return_value=None)
    mock_redis.enqueue_job = AsyncMock()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("agentgate.server.auth.verify_secret", return_value=True):
            # Send 11 requests — the 11th should be rate-limited
            for i in range(11):
                resp = await client.post(
                    "/v1/scans",
                    json={"repo_url": "https://github.com/test/agent"},
                    headers={"X-API-Key": "agk_live_testkey1.testsecret"},
                )
                if resp.status_code == 429:
                    data = resp.json()
                    assert data["error"] == "rate_limited"
                    return
            pytest.fail("Expected 429 but never received it")
```

- [ ] **Step 4: Run test to verify it fails**

Run: `uv run pytest tests/test_server/test_routes.py::test_rate_limit_returns_429_after_threshold -v`
Expected: FAIL — no rate limiting, all 11 requests return 201

- [ ] **Step 5: Implement rate limiting**

slowapi requires the `Limiter` object at decorator time. Define it in `src/agentgate/server/routes/scans.py` (avoids circular imports since `app.py` already imports the router from this file):

At the top of `src/agentgate/server/routes/scans.py`, add:

```python
from slowapi import Limiter

def _rate_limit_key(request: Request) -> str:
    """Extract parsed API key_id for rate limiting, fall back to IP."""
    raw_key = request.headers.get("X-API-Key", "")
    if "." in raw_key:
        return raw_key.split(".")[0]
    return request.client.host if request.client else "unknown"

limiter = Limiter(key_func=_rate_limit_key)
```

Add the decorator to `create_scan`:

```python
@router.post("/v1/scans", response_model=ScanResponse, status_code=201)
@limiter.limit("10/minute")
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    key_id: str = Depends(authenticate),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
):
    # ... rest unchanged ...
```

In `src/agentgate/server/app.py`, wire the limiter into the app inside `create_app()`:

```python
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from agentgate.server.routes.scans import limiter as scans_limiter

app.state.limiter = scans_limiter
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"error": "rate_limited", "detail": f"Rate limit exceeded: {exc.detail}"},
    )
```

- [ ] **Step 6: Run the rate limit test**

Run: `uv run pytest tests/test_server/test_routes.py::test_rate_limit_returns_429_after_threshold -v`
Expected: PASS

- [ ] **Step 7: Run full test suite**

Run: `uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml uv.lock src/agentgate/server/app.py src/agentgate/server/routes/scans.py tests/test_server/test_routes.py
git commit -m "Add per-API-key rate limiting on POST /v1/scans"
```

---

### Task 10: CORS — explicit origins only

**Files:**
- Modify: `src/agentgate/server/app.py`
- Test: `tests/test_server/test_routes.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_server/test_routes.py`:

```python
@pytest.mark.asyncio
async def test_cors_headers_absent_when_no_env_var():
    """CORS is off by default."""
    import os
    os.environ.pop("AGENTGATE_CORS_ORIGINS", None)
    application = create_app()
    application.state.db = AsyncMock()
    application.state.db.pool = AsyncMock()
    application.state.db.pool.fetchval = AsyncMock(return_value=1)
    application.state.redis = AsyncMock()
    application.state.redis.ping = AsyncMock(return_value=True)
    application.state.webhook_secret = "test"
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.options(
            "/v1/health",
            headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"},
        )
        assert "access-control-allow-origin" not in resp.headers


@pytest.mark.asyncio
async def test_cors_headers_present_when_env_var_set():
    import os
    os.environ["AGENTGATE_CORS_ORIGINS"] = "https://promptshop.co"
    try:
        application = create_app()
        application.state.db = AsyncMock()
        application.state.db.pool = AsyncMock()
        application.state.db.pool.fetchval = AsyncMock(return_value=1)
        application.state.redis = AsyncMock()
        application.state.redis.ping = AsyncMock(return_value=True)
        application.state.webhook_secret = "test"
        transport = ASGITransport(app=application)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.options(
                "/v1/health",
                headers={"Origin": "https://promptshop.co", "Access-Control-Request-Method": "GET"},
            )
            assert resp.headers.get("access-control-allow-origin") == "https://promptshop.co"
    finally:
        del os.environ["AGENTGATE_CORS_ORIGINS"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_server/test_routes.py::test_cors_headers_present_when_env_var_set -v`
Expected: FAIL — no CORS headers

- [ ] **Step 3: Implement CORS in create_app**

In `src/agentgate/server/app.py`, add inside `create_app()` after router registration:

```python
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
```

- [ ] **Step 4: Run CORS tests**

Run: `uv run pytest tests/test_server/test_routes.py -k "cors" -v`
Expected: Both pass

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/agentgate/server/app.py tests/test_server/test_routes.py
git commit -m "Add opt-in CORS with explicit origin configuration"
```

---

### Task 11: Static auth detection and GeneratedRuntimeProfile.auth_likely

**Files:**
- Modify: `src/agentgate/trust/runtime/submission_profile.py:148-164`
- Modify: `src/agentgate/trust/models.py:172-187`
- Test: `tests/test_trust/test_submission_profile.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_trust/test_submission_profile.py`:

```python
def test_auth_likely_true_for_fastapi_depends_auth(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["uvicorn", "app:app"]\n'
    )
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n"
        "def get_current_user(): pass\n"
        "@app.get('/data')\n"
        "def read_data(user=Depends(get_current_user)): pass\n"
    )
    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest=None,
        dependencies=[],
        runtime_env={},
        enforce_production_contract=True,
    )
    assert profile.auth_likely is True


def test_auth_likely_true_for_login_required_decorator(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["uvicorn", "app:app"]\n'
    )
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/data')\n"
        "@login_required\n"
        "def read_data(): pass\n"
    )
    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest=None,
        dependencies=[],
        runtime_env={},
        enforce_production_contract=True,
    )
    assert profile.auth_likely is True


def test_auth_likely_true_for_authorization_header(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["uvicorn", "app:app"]\n'
    )
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n"
        "@app.get('/data')\n"
        'def read_data(request: Request):\n'
        '    token = request.headers.get("Authorization")\n'
    )
    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest=None,
        dependencies=[],
        runtime_env={},
        enforce_production_contract=True,
    )
    assert profile.auth_likely is True


def test_auth_likely_false_for_plain_fastapi_app(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["uvicorn", "app:app"]\n'
    )
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/health')\n"
        "def health(): return {'status': 'ok'}\n"
    )
    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest=None,
        dependencies=[],
        runtime_env={},
        enforce_production_contract=True,
    )
    assert profile.auth_likely is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_trust/test_submission_profile.py -k "auth_likely" -v`
Expected: FAIL — `GeneratedRuntimeProfile` has no `auth_likely` attribute

- [ ] **Step 3: Add auth_likely field to both GeneratedRuntimeProfile definitions**

In `src/agentgate/trust/runtime/submission_profile.py`, add to the dataclass (after `notes` field, line 164):

```python
auth_likely: bool = False
```

In `src/agentgate/trust/models.py`, add to the Pydantic model (after `notes` field, line 187):

```python
auth_likely: bool = False
```

- [ ] **Step 4: Implement _detect_auth_signals function**

In `src/agentgate/trust/runtime/submission_profile.py`, add a compiled regex list and the detection function before `build_submission_profile`:

```python
import re as _re

_AUTH_PATTERNS: list[_re.Pattern] = [
    _re.compile(r"Depends\s*\(\s*(?:get_current_user|verify_token|api_key|get_api_key|authenticate|auth)", _re.IGNORECASE),
    _re.compile(r"@(?:login_required|requires_auth|authenticated|auth_required)", _re.IGNORECASE),
    _re.compile(r'request\.headers\.get\s*\(\s*["\'](?:Authorization|X-API-Key)["\']', _re.IGNORECASE),
    _re.compile(r"(?:jwt\.decode|jwt\.verify|oauth)", _re.IGNORECASE),
    _re.compile(r"(?:HTTPBearer|HTTPBasic|SecurityScopes)\s*\(", _re.IGNORECASE),
]


def _detect_auth_signals(source_dir: Path) -> bool:
    """Scan source files for auth patterns. Returns True if any match."""
    for path in source_dir.rglob("*.py"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for pattern in _AUTH_PATTERNS:
            if pattern.search(text):
                return True
    return False
```

- [ ] **Step 5: Call _detect_auth_signals in build_submission_profile**

In `build_submission_profile`, after line 217 (`profile.http_supported = _infer_http_supported(...)`) and before the `if not profile.http_supported` check, add:

```python
profile.auth_likely = _detect_auth_signals(source_dir)
```

- [ ] **Step 6: Run auth detection tests**

Run: `uv run pytest tests/test_trust/test_submission_profile.py -k "auth_likely" -v`
Expected: All 4 pass

- [ ] **Step 7: Run full test suite**

Run: `uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 8: Commit**

```bash
git add src/agentgate/trust/runtime/submission_profile.py src/agentgate/trust/models.py tests/test_trust/test_submission_profile.py
git commit -m "Add static auth detection as operational metadata on GeneratedRuntimeProfile"
```

---

### Task 12: Attack hints bridge and report enrichment for auth_required failures

**Files:**
- Modify: `src/agentgate/services/scan_runner.py:746-775` (attack hints) and `490-515` (ProbeError catch)
- Test: `tests/test_services/test_scan_runner.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_services/test_scan_runner.py`:

```python
def test_build_attack_hints_includes_auth_signal():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    mock_profile = GeneratedRuntimeProfile(auth_likely=True)
    mock_result = MagicMock(spec=TrustScanResult)
    mock_result.agent_overview = None
    mock_result.findings = []
    mock_result.generated_runtime_profile = mock_profile
    hints = runner._build_attack_hints(mock_result)
    assert "auth_signal:detected" in hints


def test_build_attack_hints_omits_auth_signal_when_false():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    mock_profile = GeneratedRuntimeProfile(auth_likely=False)
    mock_result = MagicMock(spec=TrustScanResult)
    mock_result.agent_overview = None
    mock_result.findings = []
    mock_result.generated_runtime_profile = mock_profile
    hints = runner._build_attack_hints(mock_result)
    assert "auth_signal:detected" not in hints
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_services/test_scan_runner.py -k "auth_signal" -v`
Expected: FAIL — `_build_attack_hints` doesn't check `generated_runtime_profile`

- [ ] **Step 3: Add auth signal to _build_attack_hints**

In `src/agentgate/services/scan_runner.py`, in `_build_attack_hints` (around line 746), add after the existing findings loop (before the dedup block):

```python
generated_profile = getattr(result, "generated_runtime_profile", None)
if generated_profile is not None and getattr(generated_profile, "auth_likely", False):
    hints.append("auth_signal:detected")
```

- [ ] **Step 4: Run attack hints tests**

Run: `uv run pytest tests/test_services/test_scan_runner.py -k "auth_signal" -v`
Expected: Both pass

- [ ] **Step 5: Enrich report detail in the ProbeError catch block**

In `src/agentgate/services/scan_runner.py`, update the `except ProbeError as exc:` block to add enriched detail when `failure_reason == "auth_required"`:

After `failure_reason = self._classify_probe_failure(exc)`, and before constructing `report_payload`, add:

```python
if failure_reason == "auth_required":
    generated_profile = self._generated_profile_from_phase(source_review)
    auth_likely = generated_profile.auth_likely if generated_profile else False
    if auth_likely:
        error = (
            f"Agent returned HTTP {exc.status_code}. "
            "Static analysis detected auth patterns confirming the agent requires "
            "authentication credentials not available in sandbox."
        )
    else:
        error = (
            f"Agent returned HTTP {exc.status_code}. "
            "No auth patterns were detected in source — the "
            f"{exc.status_code} may be from an upstream dependency or "
            "middleware not visible in code."
        )
```

- [ ] **Step 6: Run full test suite**

Run: `uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add src/agentgate/services/scan_runner.py tests/test_services/test_scan_runner.py
git commit -m "Bridge auth_likely into attack hints and enrich auth_required failure detail"
```

---

### Task 13: Fix ruff lint errors in worker/settings.py

**Files:**
- Modify: `src/agentgate/worker/settings.py:1-16`

- [ ] **Step 1: Run ruff to confirm current errors**

Run: `uv run ruff check src/agentgate/worker/settings.py`
Expected: 5 E402 errors for imports not at top of file

- [ ] **Step 2: Fix import ordering**

Consolidate all imports at the top of `src/agentgate/worker/settings.py`. Replace lines 1-16:

```python
from __future__ import annotations

import logging
import os
from pathlib import Path

from arq.connections import RedisSettings

from agentgate.server.db import Database
from agentgate.server.urls import resolve_public_base_url
from agentgate.services.scan_runner import ScanRunner
from agentgate.trust.runtime.railway_auth import (
    ensure_linked_railway_workspace,
    materialize_railway_cli_config,
)
from agentgate.worker.tasks import run_scan_job

logger = logging.getLogger(__name__)
```

- [ ] **Step 3: Run ruff to confirm clean**

Run: `uv run ruff check src/agentgate/worker/settings.py`
Expected: No errors

- [ ] **Step 4: Run full test suite**

Run: `uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/worker/settings.py
git commit -m "Fix import ordering in worker settings"
```

---

### Task 14: Final verification

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest tests/ -x -q`
Expected: All tests pass

- [ ] **Step 2: Run ruff on full codebase**

Run: `uv run ruff check src/`
Expected: No errors (or only pre-existing non-E402 issues)

- [ ] **Step 3: Verify the error envelope on all error paths**

Run a quick manual check with the test client:

```python
# In a scratch test or REPL
from httpx import AsyncClient, ASGITransport
from agentgate.server.app import create_app
from unittest.mock import AsyncMock

app = create_app()
app.state.db = AsyncMock()
app.state.db.pool = AsyncMock()
app.state.db.pool.fetchval = AsyncMock(return_value=1)
app.state.redis = AsyncMock()
app.state.redis.ping = AsyncMock(return_value=True)
app.state.webhook_secret = "test"

# Check: 401 → {"error": "unauthorized", "detail": "..."}
# Check: 422 → {"error": "validation_error", "detail": "..."}
# Check: 404 → {"error": "not_found", "detail": "..."}
# Check: 503 → {"error": "service_unavailable", "detail": "..."}
```

- [ ] **Step 4: Verify ProbeError backward compatibility**

Run: `uv run pytest tests/ -x -q --tb=short`
Expected: All 494+ tests pass, no regressions
