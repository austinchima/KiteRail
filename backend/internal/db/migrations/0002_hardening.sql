-- Hardening columns: JSON-RPC request id on ledger entries, replay attempt
-- counter on quarantine entries. Safe to re-apply against databases that
-- were initialised before versioned migrations existed.

ALTER TABLE ledger ADD COLUMN IF NOT EXISTS request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0;
ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS replayed_at TIMESTAMPTZ;
