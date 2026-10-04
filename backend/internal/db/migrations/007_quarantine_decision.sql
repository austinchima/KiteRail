-- A held action records the rule and explanation that held it, so reviewers
-- see why without joining against the ledger.
ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS policy_rule TEXT NOT NULL DEFAULT '';
ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS explanation TEXT NOT NULL DEFAULT '';
