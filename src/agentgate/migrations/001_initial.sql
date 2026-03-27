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
