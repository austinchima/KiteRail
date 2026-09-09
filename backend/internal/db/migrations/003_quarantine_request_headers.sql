-- Only replay-safe protocol headers belong here; agent credentials are never stored.
ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS request_headers JSONB NOT NULL DEFAULT '{}';
