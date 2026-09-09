-- Older development databases used a serial integer for quarantine IDs while
-- the stable API and current sqlc bindings use UUIDs. Preserve that legacy
-- value in `legacy_id` and add a new opaque UUID; no request payload or
-- approval record is discarded. Fresh databases already have UUIDs from
-- 0001_init.sql and skip this block.
DO $$
BEGIN
    -- Be defensive about databases whose migration ledger says 003 ran but
    -- whose column was created manually or by an interrupted deployment.
    ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS request_headers JSONB NOT NULL DEFAULT '{}';

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'quarantine'
          AND column_name = 'id'
          AND data_type IN ('smallint', 'integer', 'bigint')
    ) THEN
        ALTER TABLE quarantine DROP CONSTRAINT IF EXISTS quarantine_pkey;
        ALTER TABLE quarantine RENAME COLUMN id TO legacy_id;
        ALTER TABLE quarantine ADD COLUMN id UUID;
        UPDATE quarantine SET id = gen_random_uuid() WHERE id IS NULL;
        ALTER TABLE quarantine ALTER COLUMN id SET NOT NULL;
        ALTER TABLE quarantine ALTER COLUMN id SET DEFAULT gen_random_uuid();
        ALTER TABLE quarantine ADD CONSTRAINT quarantine_pkey PRIMARY KEY (id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_quarantine_legacy_id ON quarantine (legacy_id);
    END IF;
END
$$;
