CREATE TABLE IF NOT EXISTS incidents (
    thread_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high',
    site TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Second factor and lockout state. Kept in the database so a lock survives a
-- restart and applies to every API replica.
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

-- Approval ledger. Hash-chained and signed by the API; append-only in the
-- database so that direct SQL access cannot rewrite an approval after the fact.
CREATE TABLE IF NOT EXISTS approvals (
    id BIGSERIAL PRIMARY KEY,
    thread_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    feedback TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    evidence JSONB NOT NULL,
    created_at TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS approvals_thread_idx ON approvals (thread_id);

CREATE OR REPLACE FUNCTION approvals_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'approvals is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS approvals_no_mutate ON approvals;
CREATE TRIGGER approvals_no_mutate
BEFORE UPDATE OR DELETE ON approvals
FOR EACH ROW EXECUTE FUNCTION approvals_append_only();

-- Durable investigation jobs. Leased by workers with FOR UPDATE SKIP LOCKED.
CREATE TABLE IF NOT EXISTS investigation_jobs (
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'queued',
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS investigation_jobs_poll_idx
    ON investigation_jobs (status, available_at, id);
CREATE INDEX IF NOT EXISTS investigation_jobs_thread_idx
    ON investigation_jobs (thread_id, created_at DESC);

CREATE TABLE IF NOT EXISTS worker_heartbeats (
    worker_id TEXT PRIMARY KEY,
    concurrency INT NOT NULL DEFAULT 1,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    meta JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS execution_results (
    operation_key TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    result JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);