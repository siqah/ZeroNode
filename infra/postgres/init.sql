CREATE TABLE IF NOT EXISTS incidents (
    thread_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
