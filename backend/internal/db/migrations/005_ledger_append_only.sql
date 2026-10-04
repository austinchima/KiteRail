-- The ledger is append-only. The hash chain makes tampering detectable; these
-- triggers make accidental or application-level mutation impossible. A
-- deliberate operator purge (retention, test isolation) must opt in for one
-- transaction with: SET LOCAL kiterail.ledger_maintenance = 'on'.
-- Defense against a compromised database owner needs separate roles plus
-- external anchoring of the chain head (GET /api/v1/ledger/head).

CREATE OR REPLACE FUNCTION kiterail_ledger_append_only() RETURNS trigger AS $$
BEGIN
    IF current_setting('kiterail.ledger_maintenance', true) = 'on' THEN
        IF TG_OP = 'UPDATE' THEN
            RETURN NEW;
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'ledger is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ledger_no_update_delete ON ledger;
CREATE TRIGGER ledger_no_update_delete
    BEFORE UPDATE OR DELETE ON ledger
    FOR EACH ROW EXECUTE FUNCTION kiterail_ledger_append_only();

DROP TRIGGER IF EXISTS ledger_no_truncate ON ledger;
CREATE TRIGGER ledger_no_truncate
    BEFORE TRUNCATE ON ledger
    FOR EACH STATEMENT EXECUTE FUNCTION kiterail_ledger_append_only();
