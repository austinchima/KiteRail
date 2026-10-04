-- Records which policy bundle produced each decision. Entries written before
-- this column existed keep '' and their original hashes (the field only joins
-- the hash when non-empty), so existing chains still verify.
ALTER TABLE ledger ADD COLUMN IF NOT EXISTS policy_version TEXT NOT NULL DEFAULT '';
