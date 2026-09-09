package ledger

import (
	"context"
	"database/sql"
	"sync"
	"testing"

	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/dbtest"
	"github.com/stretchr/testify/require"
)

func openTestDB(t *testing.T) *sql.DB {
	return dbtest.Open(t)
}

func TestLedger_RoundtripWithVerify(t *testing.T) {
	sqlDB := openTestDB(t)

	store, err := New(sqlDB)
	require.NoError(t, err)

	dbtest.Reset(t, sqlDB, "ledger")

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
	sqlDB := openTestDB(t)

	store, err := New(sqlDB)
	require.NoError(t, err)

	dbtest.Reset(t, sqlDB, "ledger")

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
	sqlDB := openTestDB(t)

	store, err := New(sqlDB)
	require.NoError(t, err)

	dbtest.Reset(t, sqlDB, "ledger")

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
