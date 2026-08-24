-- name: GetLatestLedgerEntry :one
SELECT COALESCE(hash, ''), COALESCE(seq_num, 0)
FROM ledger ORDER BY seq_num DESC LIMIT 1 FOR UPDATE;

-- name: InsertLedgerEntry :exec
INSERT INTO ledger (seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ListLedgerEntriesAsc :many
SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash
FROM ledger ORDER BY seq_num ASC;

-- name: ListRecentLedgerEntries :many
SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash
FROM ledger ORDER BY seq_num DESC LIMIT 100;

-- name: CountTodayActions :one
SELECT COUNT(*) FROM ledger WHERE timestamp >= CURRENT_DATE;

-- name: CountTodayViolations :one
SELECT COUNT(*) FROM ledger WHERE timestamp >= CURRENT_DATE AND decision IN ('deny', 'quarantine');

-- name: GetLedgerEntry :one
SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash
FROM ledger WHERE seq_num = $1;