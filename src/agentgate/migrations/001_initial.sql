CREATE TABLE IF NOT EXISTS api_keys (
    key_id      TEXT PRIMARY KEY,
    key_hash    TEXT NOT NULL UNIQUE,
    name        TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'pending',
    phase           TEXT,
    status_detail   TEXT,
    progress_current INTEGER,
    progress_total  INTEGER,
    repo_url        TEXT NOT NULL,
    git_ref         TEXT,
    entrypoint      TEXT,
    runtime         TEXT DEFAULT 'python',
    manifest_path   TEXT,
    dockerfile_path TEXT,
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

CREATE TABLE IF NOT EXISTS scan_events (
    id               BIGSERIAL PRIMARY KEY,
    scan_id          TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    event_type       TEXT NOT NULL,
    status           TEXT NOT NULL,
    phase            TEXT,
    detail           TEXT,
    progress_current INTEGER,
    progress_total   INTEGER,
    payload          JSONB,
    created_at       TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scans_api_key_id ON scans(api_key_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_idempotency ON scans(api_key_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_events_scan_id_id ON scan_events(scan_id, id);

ALTER TABLE scans ADD COLUMN IF NOT EXISTS dockerfile_path TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS git_ref TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS phase TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS status_detail TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress_current INTEGER;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress_total INTEGER;
