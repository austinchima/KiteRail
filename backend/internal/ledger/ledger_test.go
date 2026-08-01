package ledger

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS ledger").WillReturnResult(sqlmock.NewResult(1, 1))

	store, err := New(db)
	require.NoError(t, err)
	assert.NotNil(t, store)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Append(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store := &Store{db: db}
	entry := LedgerEntry{
		Agent:       "agent_test",
		Tool:        "tool_test",
		Decision:    "allow",
		PolicyRule:  "rule_test",
		PayloadHash: "hash_test",
	}

	mock.ExpectBegin()
	// Mock previous hash query
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
		).WillReturnResult(sqlmock.NewResult(43, 1))
	mock.ExpectCommit()

	err = store.Append(context.Background(), entry)
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Verify(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store := &Store{db: db}

	entry1 := LedgerEntry{
		SeqNum:      1,
		Timestamp:   time.Now(),
		Agent:       "agent_1",
		Tool:        "tool_1",
		Decision:    "allow",
		PayloadHash: "hash_1",
		PrevHash:    "",
	}
	entry1.Hash = calculateHash(entry1)

	entry2 := LedgerEntry{
		SeqNum:      2,
		Timestamp:   time.Now(),
		Agent:       "agent_2",
		Tool:        "tool_2",
		Decision:    "deny",
		PayloadHash: "hash_2",
		PrevHash:    entry1.Hash,
	}
	entry2.Hash = calculateHash(entry2)

	rows := sqlmock.NewRows([]string{"seq_num", "timestamp", "agent", "tool", "decision", "policy_rule", "payload_hash", "prev_hash", "hash"}).
		AddRow(entry1.SeqNum, entry1.Timestamp, entry1.Agent, entry1.Tool, entry1.Decision, entry1.PolicyRule, entry1.PayloadHash, entry1.PrevHash, entry1.Hash).
		AddRow(entry2.SeqNum, entry2.Timestamp, entry2.Agent, entry2.Tool, entry2.Decision, entry2.PolicyRule, entry2.PayloadHash, entry2.PrevHash, entry2.Hash)

	mock.ExpectQuery("SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash FROM ledger ORDER BY seq_num ASC").
		WillReturnRows(rows)

	valid, err := store.Verify(context.Background())
	require.NoError(t, err)
	assert.True(t, valid)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Verify_InvalidChain(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store := &Store{db: db}

	entry1 := LedgerEntry{
		SeqNum:      1,
		Timestamp:   time.Now(),
		Agent:       "agent_1",
		Tool:        "tool_1",
		Decision:    "allow",
		PayloadHash: "hash_1",
		PrevHash:    "",
		Hash:        "fake_hash_1", // Invalid hash
	}

	rows := sqlmock.NewRows([]string{"seq_num", "timestamp", "agent", "tool", "decision", "policy_rule", "payload_hash", "prev_hash", "hash"}).
		AddRow(entry1.SeqNum, entry1.Timestamp, entry1.Agent, entry1.Tool, entry1.Decision, entry1.PolicyRule, entry1.PayloadHash, entry1.PrevHash, entry1.Hash)

	mock.ExpectQuery("SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash FROM ledger ORDER BY seq_num ASC").
		WillReturnRows(rows)

	valid, err := store.Verify(context.Background())
	require.NoError(t, err)
	assert.False(t, valid)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}
