package ledger

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"

	"github.com/austinchima/kiterail/internal/db"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

const integrationDBLockKey int64 = 4242420427

func openTestDB(t *testing.T) *sql.DB {
	dsn := os.Getenv("KITERAIL_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KITERAIL_POSTGRES_DSN not set")
	}

	ctx := context.Background()
	lockDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	lockDB.SetMaxOpenConns(1)
	lockDB.SetMaxIdleConns(1)
	if err := lockDB.PingContext(ctx); err != nil {
		lockDB.Close()
		t.Fatalf("failed to ping DB: %v", err)
	}
	if _, err := lockDB.ExecContext(ctx, "SELECT pg_advisory_lock($1)", integrationDBLockKey); err != nil {
		lockDB.Close()
		t.Fatalf("failed to acquire DB test lock: %v", err)
	}

	dbConn, err := sql.Open("postgres", dsn)
	if err != nil {
		_, _ = lockDB.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", integrationDBLockKey)
		lockDB.Close()
		t.Fatalf("failed to open DB: %v", err)
	}
	if err := dbConn.PingContext(ctx); err != nil {
		dbConn.Close()
		_, _ = lockDB.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", integrationDBLockKey)
		lockDB.Close()
		t.Fatalf("failed to ping DB: %v", err)
	}
	if err := db.Migrate(ctx, dbConn); err != nil {
		dbConn.Close()
		_, _ = lockDB.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", integrationDBLockKey)
		lockDB.Close()
		t.Fatalf("failed to apply migrations: %v", err)
	}
	t.Cleanup(func() {
		dbConn.Close()
		_, _ = lockDB.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", integrationDBLockKey)
		lockDB.Close()
	})
	return dbConn
}

func TestLedger_RoundtripWithVerify(t *testing.T) {
	if os.Getenv("KITERAIL_POSTGRES_DSN") == "" {
		t.Skip("KITERAIL_POSTGRES_DSN not set")
	}
	sqlDB := openTestDB(t)

	store, err := New(sqlDB)
	require.NoError(t, err)

	_, err = sqlDB.ExecContext(context.Background(), "TRUNCATE ledger RESTART IDENTITY")
	require.NoError(t, err)

	entries := []db.LedgerEntry{
		{Agent: "agent_1", Tool: "tool_a", Decision: "allow", PolicyRule: "rule_a", PayloadHash: "hash_a"},
		{Agent: "agent_2", Tool: "tool_b", Decision: "quarantine", PolicyRule: "rule_b", PayloadHash: "hash_b"},
		{Agent: "agent_3", Tool: "tool_c", Decision: "deny", PolicyRule: "rule_c", PayloadHash: "hash_c"},
	}

	for _, e := range entries {
		err := store.Append(context.Background(), e)
		require.NoError(t, err)
	}

	valid, err := store.Verify(context.Background())
	require.NoError(t, err)
	if !valid {
		t.Fatal("Verify() returned false on valid chain — this is Bug A (timestamp truncation mismatch)")
	}
}

func TestLedger_RequestID_SurvivesRoundTrip(t *testing.T) {
	if os.Getenv("KITERAIL_POSTGRES_DSN") == "" {
		t.Skip("KITERAIL_POSTGRES_DSN not set")
	}
	sqlDB := openTestDB(t)

	store, err := New(sqlDB)
	require.NoError(t, err)

	_, err = sqlDB.ExecContext(context.Background(), "TRUNCATE ledger RESTART IDENTITY")
	require.NoError(t, err)

	const wantRequestID = "mcp-request-42"
	err = store.Append(context.Background(), db.LedgerEntry{
		Agent:       "agent_request_id",
		Tool:        "tool_request_id",
		Decision:    "allow",
		PolicyRule:  "rule_request_id",
		PayloadHash: "hash_request_id",
		RequestID:   wantRequestID,
	})
	require.NoError(t, err)

	var gotRequestID string
	err = sqlDB.QueryRowContext(context.Background(), "SELECT request_id FROM ledger").Scan(&gotRequestID)
	require.NoError(t, err)
	require.Equal(t, wantRequestID, gotRequestID,
		"request_id MUST be physically persisted and unchanged after the append -> DB round trip")

	valid, err := store.Verify(context.Background())
	require.NoError(t, err)
	require.True(t, valid, "Verify() MUST succeed for entries with non-empty request_id")

	recent, err := store.Query(context.Background())
	require.NoError(t, err)
	require.Len(t, recent, 1)
	require.Equal(t, wantRequestID, recent[0].RequestID,
		"generated list query MUST return the persisted request_id")

	gq := db.New(sqlDB)
	bySeqNum, err := gq.GetLedgerEntry(context.Background(), recent[0].SeqNum)
	require.NoError(t, err)
	require.Equal(t, wantRequestID, bySeqNum.RequestID,
		"GetLedgerEntry MUST return the persisted request_id")

	ascending, err := gq.ListLedgerEntriesAsc(context.Background())
	require.NoError(t, err)
	require.Len(t, ascending, 1)
	require.Equal(t, wantRequestID, ascending[0].RequestID,
		"ListLedgerEntriesAsc MUST return the persisted request_id")
}

func TestLedger_ConcurrentAppends_VerifyAndContiguousSeqNum(t *testing.T) {
	if os.Getenv("KITERAIL_POSTGRES_DSN") == "" {
		t.Skip("KITERAIL_POSTGRES_DSN not set")
	}
	sqlDB := openTestDB(t)

	store, err := New(sqlDB)
	require.NoError(t, err)

	_, err = sqlDB.ExecContext(context.Background(), "TRUNCATE ledger RESTART IDENTITY")
	require.NoError(t, err)

	const numGoroutines = 10
	const entriesPerGoroutine = 5
	var wg sync.WaitGroup
	errCh := make(chan error, numGoroutines)

	for g := range numGoroutines {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for range entriesPerGoroutine {
				e := db.LedgerEntry{
					Agent:       "agent_concurrent",
					Tool:        "tool_concurrent",
					Decision:    "allow",
					PolicyRule:  "rule_concurrent",
					PayloadHash: "hash",
				}
				if err := store.Append(context.Background(), e); err != nil {
					errCh <- err
					return
				}
			}
		}(g)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("Append failed in goroutine: %v", err)
		}
	}

	valid, err := store.Verify(context.Background())
	require.NoError(t, err)
	if !valid {
		t.Fatal("Verify() returned false after concurrent appends")
	}

	rows, err := sqlDB.QueryContext(context.Background(), "SELECT seq_num FROM ledger ORDER BY seq_num ASC")
	require.NoError(t, err)
	defer rows.Close()

	var seqNums []int64
	for rows.Next() {
		var sn int64
		if err := rows.Scan(&sn); err != nil {
			t.Fatalf("failed to scan seq_num: %v", err)
		}
		seqNums = append(seqNums, sn)
	}
	require.NoError(t, rows.Err())

	if len(seqNums) != numGoroutines*entriesPerGoroutine {
		t.Fatalf("expected %d rows, got %d", numGoroutines*entriesPerGoroutine, len(seqNums))
	}

	for i, sn := range seqNums {
		expected := int64(i + 1)
		if sn != expected {
			t.Fatalf("seq_num[%d] = %d, expected %d (not contiguous)", i, sn, expected)
		}
	}
}
