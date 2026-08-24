package quarantine

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

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS quarantine").WillReturnResult(sqlmock.NewResult(1, 1))

	store, err := New(db)
	require.NoError(t, err)
	assert.NotNil(t, store)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Create(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS quarantine").WillReturnResult(sqlmock.NewResult(1, 1))

	store, err := New(db)
	require.NoError(t, err)

	mock.ExpectQuery("INSERT INTO quarantine").
		WithArgs("agent_1", "tool_x", []byte(`{"data": "test"}`), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("1001"))

	id, err := store.Create(context.Background(), "agent_1", "tool_x", []byte(`{"data": "test"}`))
	require.NoError(t, err)
	assert.Equal(t, "1001", id)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Get(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS quarantine").WillReturnResult(sqlmock.NewResult(1, 1))

	store, err := New(db)
	require.NoError(t, err)
	now := time.Now()

	rows := sqlmock.NewRows([]string{"id", "agent_id", "tool_name", "payload", "status", "created_at", "resolved_at", "resolved_by"}).
		AddRow("1001", "agent_1", "tool_x", []byte("payload"), "pending", now, nil, "")

	mock.ExpectQuery("SELECT (.+) FROM quarantine WHERE id = \\$1").
		WithArgs("1001").
		WillReturnRows(rows)

	entry, err := store.Get(context.Background(), "1001")
	require.NoError(t, err)
	assert.Equal(t, "1001", entry.ID)
	assert.Equal(t, "agent_1", entry.AgentID)
	assert.Equal(t, "pending", entry.Status)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_List(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS quarantine").WillReturnResult(sqlmock.NewResult(1, 1))

	store, err := New(db)
	require.NoError(t, err)
	now := time.Now()

	rows := sqlmock.NewRows([]string{"id", "agent_id", "tool_name", "payload", "status", "created_at", "resolved_at", "resolved_by"}).
		AddRow("1001", "agent_1", "tool_x", []byte("payload1"), "pending", now, nil, "").
		AddRow("1002", "agent_2", "tool_y", []byte("payload2"), "pending", now, nil, "")

	mock.ExpectQuery("SELECT (.+) FROM quarantine WHERE status = \\$1").
		WithArgs("pending").
		WillReturnRows(rows)

	entries, err := store.List(context.Background(), "pending")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.Equal(t, "1001", entries[0].ID)
	assert.Equal(t, "1002", entries[1].ID)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Approve(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS quarantine").WillReturnResult(sqlmock.NewResult(1, 1))

	store, err := New(db)
	require.NoError(t, err)

	mock.ExpectExec("UPDATE quarantine SET status = \\$1, resolved_at = \\$2, resolved_by = \\$3 WHERE id = \\$4").
		WithArgs("approved", sqlmock.AnyArg(), "admin", "1001").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.Approve(context.Background(), "1001", "admin")
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Deny(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS quarantine").WillReturnResult(sqlmock.NewResult(1, 1))

	store, err := New(db)
	require.NoError(t, err)

	mock.ExpectExec("UPDATE quarantine SET status = \\$1, resolved_at = \\$2, resolved_by = \\$3, reason = \\$4 WHERE id = \\$5").
		WithArgs("denied", sqlmock.AnyArg(), "admin", "violation", "1001").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.Deny(context.Background(), "1001", "admin", "violation")
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}