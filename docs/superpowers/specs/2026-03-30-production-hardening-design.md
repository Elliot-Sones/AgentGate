# Production Hardening: API, Failure Taxonomy, Auth Detection

**Date:** 2026-03-30
**Status:** Approved
**Scope:** API hardening, structured probe failures, static auth detection as metadata

## Overview

Three workstreams to make the hosted API production-ready for PromptShop integration:

1. **Structured ProbeError + typed failure taxonomy** — factual probe observations, runner-level semantic classification
2. **API hardening** — lifespan migration, error envelope, input validation, health check, rate limiting, CORS
3. **Static auth detection** — operational metadata on GeneratedRuntimeProfile for report enrichment

No new database columns, no migrations, no changes to trust policy or verdict logic.

---

## Section 1: Structured ProbeError + Failure Taxonomy

### Problem

All probe failures collapse into `failure_reason="live_attack_unusable"`. A 401 (needs auth), 404 (wrong endpoint), and 500 (broken config) are indistinguishable to the API caller.

### Design

Two layers with a clean boundary: the probe captures factual HTTP observations, the scan runner maps those facts to the public failure taxonomy.

#### ProbeError enrichment

**File:** `src/agentgate/scanner.py:41`

Add keyword-only fields with defaults so existing callers continue to work:

```python
class ProbeError(Exception):
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

No semantic fields (no `category`). Pure observation.

#### Probe layer changes

**File:** `src/agentgate/services/scan_runner.py:850` (`_await_live_attack_readiness`)

Track the last HTTP response during the poll loop. When raising, include structured facts:

```python
raise ProbeError(
    last_error,
    status_code=last_status_code,      # int | None
    target_url=target_url,              # the chosen live target
    response_excerpt=last_body[:500],   # truncated response body
)
```

When no HTTP response was ever received (connection refused, DNS failure), `status_code` stays `None`.

**Constraint:** `endpoint_not_found` (404) must only apply to the chosen live target after discovery, not early health/docs probes. The `_await_live_attack_readiness` method already operates on the resolved target URL, so this is naturally scoped.

**Constraint:** `boot_timeout` should include whether any TCP/HTTP reachability was observed, stored in the internal report payload (not the public `failure_reason`). Track a `last_reachable: bool` alongside `last_status_code`.

#### Runner-level classification

**File:** `src/agentgate/services/scan_runner.py` — new method `_classify_probe_failure`

```python
def _classify_probe_failure(self, exc: ProbeError) -> str:
    if exc.status_code in (401, 403):
        return "auth_required"
    if exc.status_code == 404:
        return "endpoint_not_found"
    if exc.status_code is not None and exc.status_code >= 500:
        return "deployment_unusable"
    return "boot_timeout"
```

Called from `_run_live_attack_scan` where `ProbeError` is caught (around line 490). Replaces the hardcoded `"live_attack_unusable"` for probe failures.

#### Public failure taxonomy

| Reason | Trigger | Meaning |
|--------|---------|---------|
| `auth_required` | 401/403 from chosen live target | Agent requires credentials not available in sandbox |
| `endpoint_not_found` | 404 from chosen live target | Live target path doesn't exist on the agent |
| `deployment_unusable` | 5xx from chosen live target | Agent booted but isn't serving usable responses |
| `boot_timeout` | No HTTP response within timeout | Agent never became reachable |
| `live_attack_timeout` | Existing, unchanged | 12-minute overall scan timeout exceeded |
| `deployment_failed` | Existing, unchanged | Railway deployment itself failed |
| `live_attack_unusable` | Narrowed | Agent responded but 0 security tests executed (detectors couldn't exercise it) |

`config_required` is intentionally omitted. Ambiguous 5xx defaults to `deployment_unusable`. We only upgrade to `config_required` in a future slice if we have positive evidence (response body or logs containing missing-config indicators).

### Files changed

- `src/agentgate/scanner.py` — ProbeError class
- `src/agentgate/services/scan_runner.py` — `_await_live_attack_readiness`, `_classify_probe_failure`, `_run_live_attack_scan` catch block
- Tests for the above

---

## Section 2: API Hardening

### 2a: Lifespan migration

**File:** `src/agentgate/server/app.py`

Replace `@app.on_event("startup")` (line 27) and `@app.on_event("shutdown")` (line 48) with a single `@asynccontextmanager` lifespan function passed to `FastAPI(lifespan=...)`.

**Ownership tracking:** If `app.state.db` or `app.state.redis` is already set (injected by tests), skip initialization and skip teardown. Only tear down resources the lifespan created. Track this with local booleans (`owns_db`, `owns_redis`).

### 2b: Error envelope

**File:** `src/agentgate/server/app.py`

Register exception handlers in `create_app()`:

- `RequestValidationError` → 422, `{"error": "validation_error", "detail": "<simplified field + message>"}`
- `HTTPException` → preserve status code, map to semantic error code:
  - 401 → `"unauthorized"`
  - 404 → `"not_found"`
  - 409 → `"conflict"`
  - 429 → `"rate_limited"`
  - 503 → `"service_unavailable"`
  - other → `"api_error"`
- Catch-all `Exception` → 500, `{"error": "internal_error", "detail": "An unexpected error occurred."}`

No stack traces leaked. Consistent `{"error": str, "detail": str}` shape on every error.

### 2c: Input validation

**File:** `src/agentgate/server/models.py`

**`repo_url`** — `field_validator`:
- Must use `https://` scheme
- Reject private/internal hosts: `localhost`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `[::1]`, `fc00::/7`
- Allow GitHub tree URLs, standard `https://github.com/owner/repo` shapes, and any public HTTPS URL
- Do NOT enforce `.git` suffix or specific hosting provider

**`webhook_url`** — `field_validator`:
- Must use `https://` scheme by default
- Same private-host rejection as repo_url
- Allow `http://localhost` and `http://127.0.0.1` ONLY when `AGENTGATE_DEV_MODE=1` env var is set
- `None` passes through (webhook is optional)

**Connect-time IP validation:** `src/agentgate/server/webhook.py` — before delivering the webhook, resolve the hostname to IP addresses and reject any that fall in private/link-local/loopback ranges. This is not a reuse of `_is_private_host` (which is syntactic hostname checking). This is a separate `_resolve_and_check_ip(url: str) -> None` function that calls `socket.getaddrinfo`, checks each resolved IP against `ipaddress.ip_address(addr).is_private`, and raises before the HTTP request is made. This guards against DNS rebinding where a public hostname resolves to a private IP at send time — a case that hostname-only validation cannot catch.

**`runtime`** — Change type from `str` to `Literal["python"]`.

**Shared utility:** `_is_private_host(hostname: str) -> bool` defined in `models.py`. Parses hostname, checks against private ranges via `ipaddress` stdlib. Used by both `repo_url` and `webhook_url` validators in `models.py`. The webhook send-time guard uses the separate `_resolve_and_check_ip` function in `webhook.py` (see above), not this utility.

### 2d: Deep health check

**File:** `src/agentgate/server/routes/health.py`

Inject `Request` to access `app.state`. Probe both dependencies:

- **Postgres:** `await db.pool.fetchval("SELECT 1")` (guard `pool is not None`)
- **Redis:** `await redis.ping()` (arq pool ping)
- If either fails or is None: return 503 via `HTTPException`
- Both healthy: return `HealthResponse()` (200)

The 503 flows through the error envelope, returning `{"error": "service_unavailable", "detail": "..."}`.

### 2e: Rate limiting

**File:** `src/agentgate/server/routes/scans.py` (route-scoped, not middleware)

Add `slowapi` dependency. Rate limit only `POST /v1/scans`:

- Key function: extract the parsed `key_id` from the `X-API-Key` header (NOT the raw header value, to avoid using the secret as limiter state)
- Limit: 10 requests/minute per API key
- Limiter state object registered on `app.state` in `create_app()`
- **Exception handler wiring:** SlowAPI raises `slowapi.errors.RateLimitExceeded` when the limit is hit. Register an explicit exception handler for `RateLimitExceeded` in `create_app()` that returns the normalized envelope: `429, {"error": "rate_limited", "detail": "Rate limit exceeded: 10 per 1 minute"}`. Without this handler, SlowAPI returns its own non-standard response format that bypasses the error envelope.

**File:** `pyproject.toml` — add `slowapi` to the `server` optional dependency group.

### 2f: CORS

**File:** `src/agentgate/server/app.py`

```python
cors_origins_raw = os.environ.get("AGENTGATE_CORS_ORIGINS", "")
if cors_origins_raw:
    origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
```

- CORS is **off by default** (no env var = no middleware added)
- Explicit origins only, no wildcard with credentials
- PromptShop sets `AGENTGATE_CORS_ORIGINS=https://promptshop.co,https://app.promptshop.co`
- Local dev sets `AGENTGATE_CORS_ORIGINS=http://localhost:3000`

### Files changed

- `src/agentgate/server/app.py` — lifespan, error handlers, CORS, limiter state
- `src/agentgate/server/models.py` — input validators, `_is_private_host`, runtime Literal
- `src/agentgate/server/routes/health.py` — deep health check
- `src/agentgate/server/routes/scans.py` — rate limiter decorator, key function
- `src/agentgate/server/webhook.py` — send-time SSRF re-check
- `pyproject.toml` — `slowapi` dependency
- Tests for all of the above

---

## Section 3: Static Auth Detection as Operational Metadata

### Problem

When the deployed agent returns 401, the scan runner has no context about whether auth was expected. The failure message is generic.

### Design

Detect auth patterns in source code during the submission profile build. Store the result as operational metadata on `GeneratedRuntimeProfile`. The scan runner uses it to enrich failure report detail when 401/403 is observed.

#### Auth pattern detection

**File:** `src/agentgate/trust/runtime/submission_profile.py`

New function `_detect_auth_signals(source_dir: Path) -> bool`, called during `build_submission_profile()`. Scans `.py` files for:

- `Depends(get_current_user)`, `Depends(verify_token)`, `Depends(api_key_header)` and similar FastAPI auth injection patterns
- `@login_required`, `@requires_auth`, `@authenticated` decorators
- `request.headers.get("Authorization")`, `request.headers.get("X-API-Key")` header extraction
- `jwt.decode`, `jwt.verify`, `oauth` token verification
- `HTTPBearer`, `HTTPBasic`, `SecurityScopes` FastAPI security schemes

Returns `True` if any pattern matches.

#### Model changes

**Both** `GeneratedRuntimeProfile` definitions must be updated:

- `src/agentgate/trust/runtime/submission_profile.py:148` (dataclass) — add `auth_likely: bool = False`
- `src/agentgate/trust/models.py:172` (Pydantic BaseModel) — add `auth_likely: bool = False`

#### Attack hints bridge

**File:** `src/agentgate/services/scan_runner.py:746` (`_build_attack_hints`)

Add a block after the existing findings loop that emits `auth_signal:detected` as downstream metadata:

```python
generated_profile = result.generated_runtime_profile
if generated_profile and generated_profile.auth_likely:
    hints.append("auth_signal:detected")
```

This is metadata for consumers of the attack hints list. It is NOT the source of truth for failure messaging (see below).

#### Report enrichment

**File:** `src/agentgate/services/scan_runner.py` — in the `ProbeError` catch block (around line 490)

`_run_live_attack_scan` already has `source_review` in scope, which contains the generated profile. When `_classify_probe_failure` returns `"auth_required"`, read `generated_profile.auth_likely` directly from the source review's generated profile — do NOT route through attack hints, which would create avoidable indirection and allow hint generation and failure messaging to drift apart:

```python
generated_profile = self._generated_profile_from_phase(source_review)
auth_likely = generated_profile.auth_likely if generated_profile else False
```

- **With `auth_likely=True`:** Detail says "Agent returned HTTP {status_code}. Static analysis detected auth patterns confirming the agent requires authentication credentials not available in sandbox."
- **With `auth_likely=False`:** Detail says "Agent returned HTTP {status_code}. No auth patterns were detected in source — the {status_code} may be from an upstream dependency or middleware not visible in code."

This enrichment is in the report payload only. The `failure_reason` value stays `"auth_required"` either way.

### Scope guard

In this slice, auth detection is used ONLY for:
- `auth_likely` field on `GeneratedRuntimeProfile`
- `auth_signal:detected` attack hint for report context
- Enriched failure detail messages

It does NOT:
- Change detector selection
- Affect trust score or verdict
- Emit trust findings
- Skip or modify probe behavior

### Files changed

- `src/agentgate/trust/runtime/submission_profile.py` — `_detect_auth_signals`, `auth_likely` field, call in `build_submission_profile`
- `src/agentgate/trust/models.py` — `auth_likely` field on Pydantic mirror
- `src/agentgate/services/scan_runner.py` — attack hints bridge, report detail enrichment
- Tests for the above

---

## Lint cleanup

**File:** `src/agentgate/worker/settings.py`

Fix the 5 ruff E402 import ordering errors. Consolidate imports to top of file.

---

## Dependency additions

- `slowapi` added to `pyproject.toml` under `[project.optional-dependencies] server`

---

## Test strategy

Each section has focused unit tests:

- **Section 1:** Test `ProbeError` carries structured fields. Test `_classify_probe_failure` maps status codes correctly. Test `_run_live_attack_scan` uses classified reasons in output. Test `boot_timeout` includes reachability detail in payload.
- **Section 2:** Test lifespan creates/tears down resources only when not pre-injected. Test error envelope returns correct codes for each exception type. Test input validators reject private hosts, non-HTTPS, empty URLs. Test health check returns 503 when db/redis unavailable. Test rate limiter returns 429 after threshold. Test CORS headers present only when env var set.
- **Section 3:** Test `_detect_auth_signals` finds known patterns. Test `auth_likely=False` when no patterns present. Test attack hints include `auth_signal:detected`. Test report detail enrichment text varies based on auth signal presence.

All existing tests must continue to pass — ProbeError changes are backward-compatible (keyword-only defaults), model changes add optional fields.
