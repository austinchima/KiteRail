-- name: CreateQuarantineEntry :one
INSERT INTO quarantine (agent_id, tool_name, payload, status, created_at)
VALUES ($1, $2, $3, 'pending', $4) RETURNING id::text;

-- name: GetQuarantineEntry :one
SELECT id::text, COALESCE(agent_id, ''), COALESCE(tool_name, ''), payload, status, created_at, resolved_at, COALESCE(resolved_by, '')
FROM quarantine WHERE id = $1;

-- name: ListQuarantineByStatus :many
SELECT id::text, COALESCE(agent_id, ''), COALESCE(tool_name, ''), payload, status, created_at, resolved_at, COALESCE(resolved_by, '')
FROM quarantine WHERE status = $1;

-- name: ApproveQuarantineEntry :execresult
UPDATE quarantine SET status = $1, resolved_at = $2, resolved_by = $3
WHERE id = $4 AND status IN ('pending', 'replay_failed');

-- name: MarkReplayFailed :exec
UPDATE quarantine SET status = 'replay_failed' WHERE id = $1 AND status = 'approved';

-- name: DenyQuarantineEntry :execresult
UPDATE quarantine SET status = $1, resolved_at = $2, resolved_by = $3, reason = $4
WHERE id = $5 AND status IN ('pending', 'replay_failed');

-- name: GetQuarantineEntryForReplay :one
SELECT id::text, COALESCE(agent_id, ''), COALESCE(tool_name, ''), payload, status, created_at, resolved_at, COALESCE(resolved_by, '')
FROM quarantine WHERE id = $1;