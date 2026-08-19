CREATE TABLE IF NOT EXISTS incidents (
    thread_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high',
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
