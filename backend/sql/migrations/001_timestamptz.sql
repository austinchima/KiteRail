-- Migration 001: Convert TIMESTAMP columns to TIMESTAMPTZ for timezone safety
-- This ensures consistent timestamp handling between Go time.Time and Postgres storage.

-- Ledger table: timestamp column
ALTER TABLE ledger ALTER COLUMN timestamp TYPE TIMESTAMPTZ USING timestamp AT TIME ZONE 'UTC';

-- Quarantine table: created_at column
ALTER TABLE quarantine ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

-- Quarantine table: resolved_at column
ALTER TABLE quarantine ALTER COLUMN resolved_at TYPE TIMESTAMPTZ USING resolved_at AT TIME ZONE 'UTC';