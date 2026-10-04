-- name: GetLatestLedgerEntry :one
SELECT COALESCE(hash, ''), COALESCE(seq_num, 0)
FROM ledger ORDER BY seq_num DESC LIMIT 1 FOR UPDATE;

-- name: InsertLedgerEntry :exec
INSERT INTO ledger (seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash, request_id, policy_version)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: ListLedgerEntriesAsc :many
SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash, request_id, policy_version
FROM ledger ORDER BY seq_num ASC;

-- name: ListRecentLedgerEntries :many
SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash, request_id, policy_version
FROM ledger ORDER BY seq_num DESC LIMIT 100;

-- name: CountTodayActions :one
SELECT COUNT(*) FROM ledger WHERE timestamp >= CURRENT_DATE;

-- name: CountTodayViolations :one
SELECT COUNT(*) FROM ledger WHERE timestamp >= CURRENT_DATE AND decision IN ('deny', 'quarantine');

-- name: GetLedgerEntry :one
SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash, request_id, policy_version
FROM ledger WHERE seq_num = $1;

-- name: ListLedgerPage :many
-- Keyset pagination, newest first. Empty filters match everything.
SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash, request_id, policy_version
FROM ledger
WHERE seq_num < sqlc.arg(before_seq)::bigint
  AND (sqlc.arg(agent)::text = '' OR agent = sqlc.arg(agent)::text)
  AND (sqlc.arg(decision)::text = '' OR decision = sqlc.arg(decision)::text)
  AND (sqlc.arg(tool)::text = '' OR tool = sqlc.arg(tool)::text)
ORDER BY seq_num DESC
LIMIT sqlc.arg(page_size)::int;

-- name: GetLedgerHead :one
SELECT seq_num, hash, timestamp FROM ledger ORDER BY seq_num DESC LIMIT 1;
