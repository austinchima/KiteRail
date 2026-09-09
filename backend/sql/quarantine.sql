-- name: CreateQuarantineEntry :one
INSERT INTO quarantine (agent_id, tool_name, payload, status, created_at, request_headers)
VALUES ($1, $2, $3, 'pending', $4, $5) RETURNING id::text;

-- name: GetQuarantineEntry :one
SELECT * FROM quarantine WHERE id = $1::uuid;

-- name: ListQuarantineByStatus :many
SELECT * FROM quarantine WHERE status = $1;

-- name: ApproveQuarantineEntry :execresult
UPDATE quarantine SET status = $1, resolved_at = $2, resolved_by = $3, attempts = 0
WHERE id = sqlc.arg(id)::uuid AND status IN ('pending', 'replay_failed');

-- name: MarkReplayFailed :execresult
-- Guard must match the state the worker is in when it calls this: the entry
-- was claimed to 'replaying'. A guard on 'approved' here silently matches
-- zero rows, and the :execresult RowsAffected check in the Store is what
-- turns that silent no-op into an error instead of wedging the machine.
UPDATE quarantine SET status = 'replay_failed' WHERE id = $1::uuid AND status = 'replaying';

-- name: DenyQuarantineEntry :execresult
UPDATE quarantine SET status = $1, resolved_at = $2, resolved_by = $3, reason = $4
WHERE id = sqlc.arg(id)::uuid AND status IN ('pending', 'replay_failed');

-- name: GetQuarantineEntryForReplay :one
SELECT * FROM quarantine WHERE id = $1::uuid;

-- name: ClaimApprovedForReplay :many
WITH candidates AS (
    SELECT id
    FROM quarantine
    WHERE status = 'approved'
    ORDER BY created_at, id
    LIMIT $1
    FOR UPDATE SKIP LOCKED
)
UPDATE quarantine AS q
SET status = 'replaying'
FROM candidates
WHERE q.id = candidates.id AND q.status = 'approved'
RETURNING q.*;

-- name: MarkReplayed :execresult
UPDATE quarantine SET status = 'replayed', replayed_at = NOW(), attempts = attempts + 1
WHERE id = $1::uuid AND status = 'replaying';

-- name: ReturnToApproved :execresult
UPDATE quarantine SET status = 'approved', attempts = attempts + 1
WHERE id = $1::uuid AND status = 'replaying';

-- name: RecoverStuckReplays :execrows
UPDATE quarantine SET status = 'approved' WHERE status = 'replaying';
