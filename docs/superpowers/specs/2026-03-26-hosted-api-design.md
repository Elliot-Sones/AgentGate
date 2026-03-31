# AgentGate Hosted Trust-Scanning API

**Date:** 2026-03-26
**Status:** Approved

## Overview

AgentGate becomes a hosted trust-scanning service that PromptShop calls from their platform before an agent solution goes live. PromptShop sends a submission, AgentGate runs the full trust scan pipeline in the background, and returns a verdict with evidence.

## Architecture

Split API + Worker on Railway.

```
PromptShop backend
    │
    POST /v1/scans
    │
    ▼
agentgate-api (FastAPI)
    ├── Validates API key and request
    ├── Creates scan record in Postgres (status: pending)
    ├── Enqueues job in Redis via arq
    └── Returns { id, status: "pending" }
    │
    ▼
agentgate-worker (arq)
    ├── Picks up job from Redis
    ├── Clones repo, loads manifest from manifest_path
    ├── Prepares runtime, deploys temporary environment if needed
    ├── Runs the full trust scan pipeline
    ├── Writes verdict, status, and report to Postgres
    ├── Tears down temporary environment (if created)
    └── Sends signed webhook with retries (if configured)
    │
    ▼
PromptShop polls GET /v1/scans/{id} or receives webhook
```

### Responsibilities

- **API**: request validation, job creation, result delivery
- **Worker**: executing the scan pipeline

### Railway Deployment Layout

```
Railway Project "AgentGate"
├── Service: agentgate-api
│   ├── Entry: uvicorn agentgate.server.app:create_app --factory --host 0.0.0.0 --port 8000
│   └── Env: DATABASE_URL, REDIS_URL, AGENTGATE_WEBHOOK_SECRET, AGENTGATE_PLATFORM_* secrets
├── Service: agentgate-worker
│   ├── Entry: arq agentgate.worker.settings.WorkerSettings
│   └── Env: same as API + RAILWAY_TOKEN (for deploying agents)
├── Service: redis
├── Service: postgres
└── [temporary per-scan agent deployments, created/destroyed by worker]
```

Both services share the same codebase with different entry points. RAILWAY_TOKEN lives only on the worker since the API never deploys agents. Temporary agent deployments are created by the worker during scans, not persistent services.

## API Endpoints

```
POST   /v1/scans              — Create a new scan job
GET    /v1/scans/{id}         — Get scan status + result
GET    /v1/scans/{id}/report  — Get the full report (JSON)
GET    /v1/scans              — List recent scans (paginated)
GET    /v1/health             — Health check
```

All scan endpoints are scoped to the authenticated API key. A client can only read scans it created.

`GET /v1/scans` supports pagination via `?limit=` (default 20, max 100) and `?offset=` query params.

### Create Scan Request

```json
{
  "repo_url": "https://github.com/someone/their-agent",
  "entrypoint": "main.py",
  "runtime": "python",
  "manifest_path": "trust_manifest.yaml",
  "webhook_url": "https://promptshop.co/webhooks/agentgate"
}
```

`manifest_path` is a path inside the repo, not an external URL. Optional — the scan works without it but produces richer results with a manifest to compare declared vs actual behavior.

### Idempotency

`POST /v1/scans` accepts an optional `Idempotency-Key` header. If a request arrives with a key that matches a previously created scan, the API returns the existing scan record instead of creating a duplicate. Keys are scoped to the authenticated API key and expire after 24 hours. This prevents duplicate scans from client retries on timeout or network errors.

### Submission Source (v1 Scope)

v1 supports public GitHub repos only. This matches PromptShop's current seller flow where agents are submitted as public GitHub repo URLs. Private repo auth and direct archive uploads are future extensions — the `scan_runner.py` abstraction layer is designed so adding new source types does not require changes to the API or worker.

### Scan Status Response (pending/running)

```json
{
  "id": "scan_abc123",
  "status": "scanning",
  "created_at": "2026-03-26T22:00:00Z",
  "updated_at": "2026-03-26T22:01:15Z",
  "verdict": null
}
```

The `status` field reflects the current scan stage. No separate progress field — `status` is the progress indicator.

### Scan Status Response (completed)

```json
{
  "id": "scan_abc123",
  "status": "completed",
  "created_at": "2026-03-26T22:00:00Z",
  "completed_at": "2026-03-26T22:04:30Z",
  "verdict": "manual_review",
  "score": {
    "checks_run": 11,
    "checks_passed": 8,
    "checks_failed": 3
  },
  "findings_summary": [],
  "report_url": "/v1/scans/scan_abc123/report"
}
```

### Scan Statuses

`pending` → `cloning` → `deploying` → `scanning` → `completed` | `failed`

### Verdicts

`allow_clean` | `allow_with_warnings` | `manual_review` | `block`

## Authentication

API key format: `agk_live_<key_id>.<secret>`

Example: `agk_live_ps001.xK9mW2vR7nQ4pL8sT1...`

### Flow

1. Client sends `X-API-Key: agk_live_ps001.xK9mW2v...` header
2. Server parses `key_id` ("ps001") from the key
3. Server fetches the row from `api_keys` by `key_id`
4. Server verifies the secret against the stored bcrypt hash
5. If valid, attaches `api_key_id` to request context
6. If invalid, returns 401

### Key Management CLI

```bash
agentgate api-key create --name "PromptShop Production"
# → Created API key: agk_live_ps001.xK9mW2vR7nQ4pL8sT1...
# → Store this key securely. It cannot be retrieved again.
```

Keys are never stored raw. Only the bcrypt hash of the secret is persisted.

## Webhook Delivery

When a scan completes and `webhook_url` is set:

```
POST {webhook_url}
X-AgentGate-Signature: sha256=<HMAC(body + timestamp, webhook_secret)>
X-AgentGate-Timestamp: 1711497600
Content-Type: application/json

{
  "event": "scan.completed",
  "scan_id": "scan_abc123",
  "verdict": "manual_review",
  "score": { "checks_run": 11, "checks_passed": 8, "checks_failed": 3 },
  "report_url": "https://agentgate-api.up.railway.app/v1/scans/scan_abc123/report"
}
```

### Webhook Signing

Webhooks are signed with a global `AGENTGATE_WEBHOOK_SECRET` environment variable, separate from API keys. This keeps inbound auth and outbound verification decoupled, allowing independent rotation.

- Signature: `HMAC-SHA256(raw_body + timestamp, webhook_secret)`
- Timestamp header prevents replay attacks
- Retries 3 times with exponential backoff (1s, 5s, 25s) on failure
- Webhook failures do not affect the scan — the report is always available via polling

Per-client webhook secrets are a future extension if multiple clients need independent signing.

## Database Schema

```sql
CREATE TABLE scans (
    id            TEXT PRIMARY KEY,
    status        TEXT NOT NULL,
    repo_url      TEXT NOT NULL,
    entrypoint    TEXT,
    runtime       TEXT DEFAULT 'python',
    manifest_path TEXT,
    webhook_url   TEXT,
    api_key_id    TEXT NOT NULL,
    verdict       TEXT,
    score         JSONB,
    report        JSONB,
    error         TEXT,
    created_at    TIMESTAMPTZ DEFAULT now(),
    updated_at    TIMESTAMPTZ DEFAULT now(),
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ
);

CREATE TABLE api_keys (
    key_id      TEXT PRIMARY KEY,
    key_hash    TEXT NOT NULL UNIQUE,
    name        TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);
```

Status and verdict are TEXT in Postgres, enums in application code. The `report` column holds the full JSON trust report. Large artifacts (logs, HTML, raw evidence) can move to object storage later if needed.

Postgres is the source of truth for all scan state — status, verdicts, reports. Redis is used only as a job queue for arq; it does not store scan state.

## Project Structure

```
src/agentgate/
├── server/                    # NEW — FastAPI application
│   ├── app.py                 # FastAPI app factory
│   ├── routes/
│   │   ├── scans.py           # POST/GET /v1/scans endpoints
│   │   └── health.py          # GET /v1/health
│   ├── auth.py                # API key verification middleware
│   ├── models.py              # Pydantic request/response schemas
│   ├── webhook.py             # Signed webhook delivery with retries
│   └── db.py                  # Postgres connection + queries
├── worker/                    # NEW — arq background worker
│   ├── tasks.py               # Scan job function
│   └── settings.py            # arq + Redis configuration, WorkerSettings
├── services/                  # NEW — shared orchestration layer
│   └── scan_runner.py         # Clones repo, runs TrustScanner, returns result
├── migrations/                # NEW — database migrations
│   └── 001_initial.sql        # Initial schema (scans + api_keys tables)
├── trust/                     # EXISTING — trust scan engine
│   ├── scanner.py
│   ├── checks/
│   ├── runtime/
│   └── ...
└── cli.py                     # EXISTING — add api-key management commands
```

The existing trust scan engine is not modified in its internals, but new integration work is required: `scan_runner.py` bridges the API/worker to the scanner, the CLI gains api-key management commands, and the worker handles repo cloning, deployment orchestration, status updates, and webhook delivery. This is not a zero-touch integration — the new layers are significant new code.

## New Dependencies

The following must be added to `pyproject.toml` as required dependencies for the hosted API:

| Package | Purpose |
|---------|---------|
| `fastapi` | API framework (currently optional, promote to required) |
| `uvicorn` | ASGI server (currently optional, promote to required) |
| `arq` | Redis-backed async task queue |
| `asyncpg` | Async Postgres driver |
| `bcrypt` | API key secret hashing |
| `redis[hiredis]` | Redis client for arq |

`httpx` and `pydantic` are already required dependencies.

## Storage Strategy

| Layer | Service | Purpose |
|-------|---------|---------|
| Job queue | Redis | arq job queue only |
| Source of truth | Postgres | Scan state, metadata, verdicts, JSON reports |
| Large artifacts | Object storage (future) | Logs, HTML reports, raw evidence |

Postgres is the single source of truth for all scan state. Redis is queue-only — it does not store scan results or status. Object storage is a future migration for large artifacts.

## Platform Sandbox Credentials

The worker injects sandbox credentials into temporary agent deployments:

| Integration | Env Vars |
|-------------|----------|
| Slack | SLACK_BOT_TOKEN, SLACK_SIGNING_SECRET, SLACK_TEAM_ID, SLACK_CHANNEL_ID, SLACK_APP_ID |
| Shopify | SHOPIFY_ACCESS_TOKEN, SHOPIFY_API_SECRET, SHOPIFY_API_KEY, SHOPIFY_STORE_DOMAIN |

These point to disposable sandbox environments (a free Slack workspace and a Shopify dev store) containing only fake data. The agent being scanned interacts with real APIs but cannot cause real damage.

## Known Scope Constraints (v1)

- Public GitHub repos only. Private repo auth and archive uploads are future extensions.
- Single webhook signing secret (global env var). Per-client secrets are a future extension.
- Reports stored in Postgres JSONB. Large artifacts may need object storage at scale.
- Single worker instance. Concurrent scan limits depend on Railway resources.

## Presentation Summary

AgentGate is a hosted trust-verification API for AI marketplaces. PromptShop submits seller agents for automated review. AgentGate runs deep source and runtime trust checks in the background and returns a publishability verdict with evidence. The system plugs directly into PromptShop's review workflow with zero setup on their side.
