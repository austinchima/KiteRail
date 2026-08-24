-- Schema for KiteRail ledger and quarantine tables
-- This file is used by sqlc to generate type-safe Go code

-- Ledger table for tamper-evident audit trail
CREATE TABLE IF NOT EXISTS ledger (
    seq_num SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    agent TEXT NOT NULL,
    tool TEXT NOT NULL,
    decision TEXT NOT NULL,
    policy_rule TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ledger (timestamp);
CREATE INDEX IF NOT EXISTS idx_ledger_agent ON ledger (agent);

-- Quarantine table for human-in-the-loop approval queue
CREATE TABLE IF NOT EXISTS quarantine (
    id SERIAL PRIMARY KEY,
    agent_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    payload BYTEA NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMP,
    resolved_by TEXT,
    reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine (status);
CREATE INDEX IF NOT EXISTS idx_quarantine_agent ON quarantine (agent_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_created ON quarantine (created_at);