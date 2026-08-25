-- Canonical KiteRail schema. Applied by internal/db/migrate.go in order.
-- sqlc reads the mirror of this schema from sql/schema.sql.

CREATE TABLE IF NOT EXISTS ledger (
    seq_num BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    agent TEXT NOT NULL,
    tool TEXT NOT NULL,
    decision TEXT NOT NULL,
    policy_rule TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    request_id TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ledger (timestamp);
CREATE INDEX IF NOT EXISTS idx_ledger_agent ON ledger (agent);

CREATE TABLE IF NOT EXISTS quarantine (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    payload BYTEA NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolved_by TEXT,
    reason TEXT,
    attempts INT NOT NULL DEFAULT 0,
    replayed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine (status);
CREATE INDEX IF NOT EXISTS idx_quarantine_agent ON quarantine (agent_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_created ON quarantine (created_at);
