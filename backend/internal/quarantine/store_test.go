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

	store, err := New(db)
	require.NoError(t, err)

	mock.ExpectQuery("INSERT INTO quarantine").
		WithArgs("agent_1", "tool_x", []byte(`{"data": "test"}`), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("550e8400-e29b-41d4-a716-446655440000"))

	id, err := store.Create(context.Background(), "agent_1", "tool_x", []byte(`{"data": "test"}`))
	require.NoError(t, err)
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", id)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Get(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store, err := New(db)
	require.NoError(t, err)
	now := time.Now()

	rows := sqlmock.NewRows([]string{"id", "agent_id", "tool_name", "payload", "status", "created_at", "resolved_at", "resolved_by", "reason", "attempts", "replayed_at"}).
		AddRow("550e8400-e29b-41d4-a716-446655440000", "agent_1", "tool_x", []byte("payload"), "pending", now, nil, "", nil, 0, nil)

	mock.ExpectQuery("SELECT (.+) FROM quarantine WHERE id = \\$1::uuid").
		WithArgs("550e8400-e29b-41d4-a716-446655440000").
		WillReturnRows(rows)

	entry, err := store.Get(context.Background(), "550e8400-e29b-41d4-a716-446655440000")
	require.NoError(t, err)
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", entry.ID)
	assert.Equal(t, "agent_1", entry.AgentID)
	assert.Equal(t, "pending", entry.Status)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_List(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store, err := New(db)
	require.NoError(t, err)
	now := time.Now()

	rows := sqlmock.NewRows([]string{"id", "agent_id", "tool_name", "payload", "status", "created_at", "resolved_at", "resolved_by", "reason", "attempts", "replayed_at"}).
		AddRow("550e8400-e29b-41d4-a716-446655440000", "agent_1", "tool_x", []byte("payload1"), "pending", now, nil, "", nil, 0, nil).
		AddRow("550e8400-e29b-41d4-a716-446655440001", "agent_2", "tool_y", []byte("payload2"), "pending", now, nil, "", nil, 0, nil)

	mock.ExpectQuery("SELECT (.+) FROM quarantine WHERE status = \\$1").
		WithArgs("pending").
		WillReturnRows(rows)

	entries, err := store.List(context.Background(), "pending")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", entries[0].ID)
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440001", entries[1].ID)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Approve(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store, err := New(db)
	require.NoError(t, err)

	mock.ExpectExec("UPDATE quarantine SET status = \\$1, resolved_at = \\$2, resolved_by = \\$3, attempts = 0 WHERE id = \\$4::uuid").
		WithArgs("approved", sqlmock.AnyArg(), sqlmock.AnyArg(), "550e8400-e29b-41d4-a716-446655440000").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.Approve(context.Background(), "550e8400-e29b-41d4-a716-446655440000", "admin")
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestStore_Deny(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store, err := New(db)
	require.NoError(t, err)

	mock.ExpectExec("UPDATE quarantine SET status = \\$1, resolved_at = \\$2, resolved_by = \\$3, reason = \\$4 WHERE id = \\$5::uuid").
		WithArgs("denied", sqlmock.AnyArg(), sqlmock.AnyArg(), "violation", "550e8400-e29b-41d4-a716-446655440000").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.Deny(context.Background(), "550e8400-e29b-41d4-a716-446655440000", "admin", "violation")
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}
