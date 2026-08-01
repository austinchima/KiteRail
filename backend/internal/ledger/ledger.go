package ledger

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// Schema represents the ledger table.
const Schema = `
CREATE TABLE IF NOT EXISTS ledger (
    seq_num SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    agent TEXT,
    tool TEXT,
    decision TEXT,
    policy_rule TEXT,
    payload_hash TEXT,
    prev_hash TEXT,
    hash TEXT
);
`

// LedgerEntry represents an entry in the audit ledger.
type LedgerEntry struct {
	SeqNum      int
	Timestamp   time.Time
	Agent       string
	Tool        string
	Decision    string
	PolicyRule  string
	PayloadHash string
	PrevHash    string
	Hash        string
}

// LedgerStats represents aggregated stats.
type LedgerStats struct {
	TotalActionsToday int
	PolicyViolations  int
}

// Store represents the ledger storage.
type Store struct {
	db *sql.DB
}

// New creates a new ledger Store.
func New(db *sql.DB) (*Store, error) {
	if _, err := db.Exec(Schema); err != nil {
		return nil, fmt.Errorf("failed to create ledger schema: %w", err)
	}
	return &Store{db: db}, nil
}

func calculateHash(entry LedgerEntry) string {
	data := fmt.Sprintf("%d%s%s%s%s%s%s",
		entry.SeqNum,
		entry.Timestamp.UTC().Format(time.RFC3339Nano),
		entry.Agent,
		entry.Tool,
		entry.Decision,
		entry.PayloadHash,
		entry.PrevHash,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Append appends a new entry to the ledger.
// The transaction runs at SERIALIZABLE isolation to guarantee hash-chain ordering.
// On serialization failure (SQLSTATE 40001), the operation retries up to 3 times
// with brief backoff before returning an error.
func (s *Store) Append(ctx context.Context, entry LedgerEntry) error {
	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		err := s.appendOnce(ctx, entry)
		if err == nil {
			return nil
		}
		// Postgres serialization failure: "ERROR 40001 (serialization_failure)"
		if isSerializationFailure(err) && attempt < maxRetries-1 {
			// Brief backoff: 5ms, 10ms, ...
			time.Sleep(time.Duration(5*(attempt+1)) * time.Millisecond)
			continue
		}
		return err
	}
	return fmt.Errorf("ledger append failed after %d attempts", maxRetries)
}

// isSerializationFailure detects Postgres serialization failures (SQLSTATE 40001).
func isSerializationFailure(err error) bool {
	if err == nil {
		return false
	}
	return len(err.Error()) >= 5 && err.Error()[:5] == "pq: E" &&
		(containsStr(err.Error(), "40001") || containsStr(err.Error(), "serialization"))
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && findStr(s, sub))
}

func findStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func (s *Store) appendOnce(ctx context.Context, entry LedgerEntry) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}
	defer tx.Rollback()

	var prevHash string
	var seqNum int
	err = tx.QueryRowContext(ctx, "SELECT COALESCE(hash, ''), COALESCE(seq_num, 0) FROM ledger ORDER BY seq_num DESC LIMIT 1 FOR UPDATE").Scan(&prevHash, &seqNum)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to get previous hash: %w", err)
	}

	entry.PrevHash = prevHash
	entry.SeqNum = seqNum + 1
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	entry.Hash = calculateHash(entry)

	_, err = tx.ExecContext(ctx,
		"INSERT INTO ledger (seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		entry.SeqNum, entry.Timestamp, entry.Agent, entry.Tool, entry.Decision, entry.PolicyRule, entry.PayloadHash, entry.PrevHash, entry.Hash,
	)
	if err != nil {
		return fmt.Errorf("failed to insert ledger entry: %w", err)
	}

	return tx.Commit()
}

// Verify walks the chain and verifies all hashes.
func (s *Store) Verify(ctx context.Context) (bool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash FROM ledger ORDER BY seq_num ASC")
	if err != nil {
		return false, fmt.Errorf("failed to query ledger: %w", err)
	}
	defer rows.Close()

	var prevHash string
	for rows.Next() {
		var entry LedgerEntry
		if err := rows.Scan(&entry.SeqNum, &entry.Timestamp, &entry.Agent, &entry.Tool, &entry.Decision, &entry.PolicyRule, &entry.PayloadHash, &entry.PrevHash, &entry.Hash); err != nil {
			return false, fmt.Errorf("failed to scan ledger entry: %w", err)
		}
		
		if entry.PrevHash != prevHash {
			return false, nil
		}
		
		expectedHash := calculateHash(entry)
		if entry.Hash != expectedHash {
			return false, nil
		}
		
		prevHash = entry.Hash
	}

	return true, nil
}

// Query queries ledger entries.
func (s *Store) Query(ctx context.Context) ([]LedgerEntry, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash FROM ledger ORDER BY seq_num DESC LIMIT 100")
	if err != nil {
		return nil, fmt.Errorf("failed to query ledger: %w", err)
	}
	defer rows.Close()

	var entries []LedgerEntry
	for rows.Next() {
		var entry LedgerEntry
		if err := rows.Scan(&entry.SeqNum, &entry.Timestamp, &entry.Agent, &entry.Tool, &entry.Decision, &entry.PolicyRule, &entry.PayloadHash, &entry.PrevHash, &entry.Hash); err != nil {
			return nil, fmt.Errorf("failed to scan ledger entry: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Stats returns aggregated stats for today.
func (s *Store) Stats(ctx context.Context) (LedgerStats, error) {
	var stats LedgerStats
	
	// Total actions today
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ledger WHERE timestamp >= CURRENT_DATE").Scan(&stats.TotalActionsToday)
	if err != nil {
		return stats, err
	}
	
	// Violations today
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ledger WHERE timestamp >= CURRENT_DATE AND decision IN ('deny', 'quarantine')").Scan(&stats.PolicyViolations)
	if err != nil {
		return stats, err
	}
	
	return stats, nil
}
