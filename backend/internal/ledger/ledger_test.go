package ledger

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/austinchima/kiterail/internal/db"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	store, err := New(sqlDB)
	require.NoError(t, err)
	assert.NotNil(t, store)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Append(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	store, err := New(sqlDB)
	require.NoError(t, err)

	entry := db.LedgerEntry{
		Agent:       "agent_test",
		Tool:        "tool_test",
		Decision:    "allow",
		PolicyRule:  "rule_test",
		PayloadHash: "hash_test",
	}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT COALESCE").
		WillReturnRows(sqlmock.NewRows([]string{"hash", "seq_num"}).AddRow("prev_hash_123", 42))

	mock.ExpectExec("INSERT INTO ledger").
		WithArgs(
			43,               // seq_num
			sqlmock.AnyArg(), // timestamp
			"agent_test",
			"tool_test",
			"allow",
			"rule_test",
			"hash_test",
			"prev_hash_123",
			sqlmock.AnyArg(), // hash
			sqlmock.AnyArg(), // request_id
		).WillReturnResult(sqlmock.NewResult(43, 1))
	mock.ExpectCommit()

	err = store.Append(context.Background(), entry)
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Append_BackoffRespectsContextCancellation(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	store, err := New(sqlDB)
	require.NoError(t, err)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT COALESCE").
		WillReturnError(&pq.Error{Code: "40001"})
	mock.ExpectRollback()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(2*time.Millisecond, cancel)

	start := time.Now()
	err = store.Append(ctx, db.LedgerEntry{Agent: "agent_x"})
	cancel()
	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), time.Second,
		"canceled Append must not sleep through the backoff schedule")
}

func TestStore_Verify(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	store, err := New(sqlDB)
	require.NoError(t, err)

	entry1 := db.LedgerEntry{
		SeqNum:      1,
		Timestamp:   time.Now(),
		Agent:       "agent_1",
		Tool:        "tool_1",
		Decision:    "allow",
		PolicyRule:  "rule_1",
		PayloadHash: "hash_1",
		PrevHash:    "",
	}
	entry1.Hash = calculateHash(entry1)

	entry2 := db.LedgerEntry{
		SeqNum:      2,
		Timestamp:   time.Now(),
		Agent:       "agent_2",
		Tool:        "tool_2",
		Decision:    "deny",
		PolicyRule:  "rule_2",
		PayloadHash: "hash_2",
		PrevHash:    entry1.Hash,
	}
	entry2.Hash = calculateHash(entry2)

	rows := sqlmock.NewRows([]string{"seq_num", "timestamp", "agent", "tool", "decision", "policy_rule", "payload_hash", "prev_hash", "hash", "request_id"}).
		AddRow(entry1.SeqNum, entry1.Timestamp, entry1.Agent, entry1.Tool, entry1.Decision, entry1.PolicyRule, entry1.PayloadHash, entry1.PrevHash, entry1.Hash, "").
		AddRow(entry2.SeqNum, entry2.Timestamp, entry2.Agent, entry2.Tool, entry2.Decision, entry2.PolicyRule, entry2.PayloadHash, entry2.PrevHash, entry2.Hash, "")

	mock.ExpectQuery("SELECT (.+) FROM ledger ORDER BY seq_num ASC").
		WillReturnRows(rows)

	valid, err := store.Verify(context.Background())
	require.NoError(t, err)
	assert.True(t, valid)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Verify_InvalidChain(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	store, err := New(sqlDB)
	require.NoError(t, err)

	entry1 := db.LedgerEntry{
		SeqNum:      1,
		Timestamp:   time.Now(),
		Agent:       "agent_1",
		Tool:        "tool_1",
		Decision:    "allow",
		PolicyRule:  "rule_1",
		PayloadHash: "hash_1",
		PrevHash:    "",
		Hash:        "fake_hash_1", // Invalid hash
	}

	rows := sqlmock.NewRows([]string{"seq_num", "timestamp", "agent", "tool", "decision", "policy_rule", "payload_hash", "prev_hash", "hash", "request_id"}).
		AddRow(entry1.SeqNum, entry1.Timestamp, entry1.Agent, entry1.Tool, entry1.Decision, entry1.PolicyRule, entry1.PayloadHash, entry1.PrevHash, entry1.Hash, "")

	mock.ExpectQuery("SELECT (.+) FROM ledger ORDER BY seq_num ASC").
		WillReturnRows(rows)

	valid, err := store.Verify(context.Background())
	require.NoError(t, err)
	assert.False(t, valid)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestCalculateHash_StableAfterMicrosecondTruncation(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC) // nanosecond precision
	e := db.LedgerEntry{SeqNum: 1, Timestamp: ts, Agent: "a", Tool: "t",
		Decision: "allow", PolicyRule: "r", PayloadHash: "p", PrevHash: ""}
	h1 := calculateHash(e)
	e.Timestamp = e.Timestamp.Truncate(time.Microsecond) // simulate Postgres roundtrip
	h2 := calculateHash(e)
	if h1 != h2 {
		t.Fatalf("hash not stable across microsecond truncation")
	}
}

func TestCalculateHash_CoversPolicyRule(t *testing.T) {
	e := db.LedgerEntry{SeqNum: 1, Timestamp: time.Now(), Agent: "a", Tool: "t",
		Decision: "allow", PolicyRule: "rule_a", PayloadHash: "p"}
	h1 := calculateHash(e)
	e.PolicyRule = "rule_b"
	if calculateHash(e) == h1 {
		t.Fatalf("tampering with PolicyRule is undetectable")
	}
}
