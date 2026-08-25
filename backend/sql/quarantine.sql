-- name: CreateQuarantineEntry :one
INSERT INTO quarantine (agent_id, tool_name, payload, status, created_at)
VALUES ($1, $2, $3, 'pending', $4) RETURNING id::text;

-- name: GetQuarantineEntry :one
SELECT * FROM quarantine WHERE id = $1::uuid;

-- name: ListQuarantineByStatus :many
SELECT * FROM quarantine WHERE status = $1;

-- name: ApproveQuarantineEntry :execresult
UPDATE quarantine SET status = $1, resolved_at = $2, resolved_by = $3, attempts = 0
WHERE id = sqlc.arg(id)::uuid AND status IN ('pending', 'replay_failed');

-- name: MarkReplayFailed :exec
UPDATE quarantine SET status = 'replay_failed' WHERE id = $1::uuid AND status = 'approved';

-- name: DenyQuarantineEntry :execresult
UPDATE quarantine SET status = $1, resolved_at = $2, resolved_by = $3, reason = $4
WHERE id = sqlc.arg(id)::uuid AND status IN ('pending', 'replay_failed');

-- name: GetQuarantineEntryForReplay :one
SELECT * FROM quarantine WHERE id = $1::uuid;

-- name: ClaimApprovedForReplay :many
UPDATE quarantine SET status = 'replaying'
WHERE id IN (
    SELECT id FROM quarantine WHERE status = 'approved' ORDER BY created_at LIMIT $1
)
RETURNING *;

-- name: MarkReplayed :exec
UPDATE quarantine SET status = 'replayed', replayed_at = NOW(), attempts = attempts + 1
WHERE id = $1::uuid AND status = 'replaying';

-- name: ReturnToApproved :exec
UPDATE quarantine SET status = 'approved', attempts = attempts + 1
WHERE id = $1::uuid AND status = 'replaying';

-- name: RecoverStuckReplays :execrows
UPDATE quarantine SET status = 'approved' WHERE status = 'replaying';
