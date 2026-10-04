package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/db"
)

var heldAt = time.Date(2026, 10, 3, 9, 30, 0, 0, time.UTC)

func sampleAction() HeldAction {
	return HeldAction{
		ID: "7ab69ae4-dc75-4cd4-bff9-430f88b14c35", Agent: "treasury-agent", Tool: "swift.wire.initiate",
		Rule: "wire_high_value", Explanation: "Wire transfer exceeds $10,000.", HeldAt: heldAt,
		ReviewURL: "https://console.corp.test/#inbox",
	}
}

type captured struct {
	mu      sync.Mutex
	headers http.Header
	body    []byte
	calls   int
}

func endpoint(t *testing.T, status int) (*httptest.Server, *captured) {
	c := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.calls++
		c.headers = r.Header.Clone()
		c.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func TestWebhook_SignsEventsReceiversCanVerify(t *testing.T) {
	srv, got := endpoint(t, http.StatusAccepted)
	hook := NewWebhook(srv.URL, "whsec_0123456789abcdef0123456789")
	hook.now = func() time.Time { return time.Unix(1791030000, 0) }

	require.NoError(t, hook.Send(context.Background(), sampleAction()))
	assert.Equal(t, EventHeld, got.headers.Get("X-Elodea-Event"))
	assert.Equal(t, sampleAction().ID, got.headers.Get("X-Elodea-Delivery"), "the delivery ID lets receivers deduplicate retries")
	assert.Equal(t, "1791030000", got.headers.Get("X-Elodea-Timestamp"))
	assert.Equal(t, Sign([]byte("whsec_0123456789abcdef0123456789"), "1791030000", got.body), got.headers.Get("X-Elodea-Signature"))
	assert.NotEqual(t, Sign([]byte("wrong-secret"), "1791030000", got.body), got.headers.Get("X-Elodea-Signature"))

	var event struct {
		Type   string     `json:"type"`
		Action HeldAction `json:"action"`
	}
	require.NoError(t, json.Unmarshal(got.body, &event))
	assert.Equal(t, EventHeld, event.Type)
	assert.Equal(t, sampleAction(), event.Action)
}

func TestWebhook_UnsignedWithoutSecret(t *testing.T) {
	srv, got := endpoint(t, http.StatusOK)
	require.NoError(t, NewWebhook(srv.URL, "").Send(context.Background(), sampleAction()))
	assert.Empty(t, got.headers.Get("X-Elodea-Signature"))
}

func TestSend_FailsOnNon2xxAndNeverFollowsRedirects(t *testing.T) {
	srv, _ := endpoint(t, http.StatusInternalServerError)
	assert.Error(t, NewWebhook(srv.URL, "").Send(context.Background(), sampleAction()))

	target, hit := endpoint(t, http.StatusOK)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirect.Close)
	assert.Error(t, NewWebhook(redirect.URL, "").Send(context.Background(), sampleAction()), "a redirect is a failure")
	assert.Zero(t, hit.calls, "Elodea never follows a redirect to another host")
}

func TestSlack_MessageLinksToReviewAndEscapesAgentText(t *testing.T) {
	srv, got := endpoint(t, http.StatusOK)
	action := sampleAction()
	action.Tool = "<!channel> evil|link"
	require.NoError(t, NewSlack(srv.URL).Send(context.Background(), action))

	var decoded any
	require.NoError(t, json.Unmarshal(got.body, &decoded))
	body := fmt.Sprint(decoded) // decoded strings, as Slack will read them
	assert.Contains(t, body, "https://console.corp.test/#inbox")
	assert.Contains(t, body, "Review in Elodea")
	assert.Contains(t, body, "&lt;!channel&gt;", "an agent-chosen tool name cannot @-mention a channel")
	assert.NotContains(t, body, "<!channel>")
}

// fakeStore mimics the outbox SQL closely enough to exercise the worker.
type fakeStore struct {
	mu        sync.Mutex
	entries   map[uuid.UUID]db.Quarantine
	outbox    map[[2]string]*outboxRow
	enqueued  []string
	claimErr  error
	delivered int
}

type outboxRow struct {
	attempts  int32
	nextAt    time.Time
	delivered bool
	lastError string
}

func newFakeStore(entries ...db.Quarantine) *fakeStore {
	s := &fakeStore{entries: map[uuid.UUID]db.Quarantine{}, outbox: map[[2]string]*outboxRow{}}
	for _, e := range entries {
		s.entries[e.ID] = e
	}
	return s
}

func (s *fakeStore) EnqueueHeldNotifications(_ context.Context, channels []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enqueued = channels
	for id, e := range s.entries {
		if e.Status != "pending" {
			continue
		}
		for _, ch := range channels {
			key := [2]string{id.String(), ch}
			if _, ok := s.outbox[key]; !ok {
				s.outbox[key] = &outboxRow{}
			}
		}
	}
	return nil
}

func (s *fakeStore) ClaimDueNotifications(_ context.Context, arg db.ClaimDueNotificationsParams) ([]db.ClaimDueNotificationsRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claimErr != nil {
		return nil, s.claimErr
	}
	var rows []db.ClaimDueNotificationsRow
	for key, r := range s.outbox {
		if r.delivered || r.attempts >= arg.MaxAttempts || r.nextAt.After(time.Now()) {
			continue
		}
		r.attempts++
		r.nextAt = time.Now().Add(2 * time.Minute)
		rows = append(rows, db.ClaimDueNotificationsRow{QuarantineID: key[0], Channel: key[1], Attempts: r.attempts})
	}
	return rows, nil
}

func (s *fakeStore) MarkNotificationDelivered(_ context.Context, arg db.MarkNotificationDeliveredParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outbox[[2]string{arg.QuarantineID.String(), arg.Channel}].delivered = true
	s.delivered++
	return nil
}

func (s *fakeStore) MarkNotificationFailed(_ context.Context, arg db.MarkNotificationFailedParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.outbox[[2]string{arg.QuarantineID.String(), arg.Channel}]
	r.nextAt, r.lastError = arg.NextAttemptAt, arg.LastError
	return nil
}

func (s *fakeStore) GetQuarantineEntry(_ context.Context, id uuid.UUID) (db.Quarantine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return db.Quarantine{}, errors.New("not found")
	}
	return e, nil
}

type recordingChannel struct {
	name    string
	err     error
	mu      sync.Mutex
	actions []HeldAction
}

func (c *recordingChannel) Name() string { return c.name }
func (c *recordingChannel) Send(_ context.Context, a HeldAction) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.actions = append(c.actions, a)
	return c.err
}

func pending(status string) db.Quarantine {
	return db.Quarantine{
		ID: uuid.New(), AgentID: "treasury-agent", ToolName: "swift.wire.initiate", Status: status,
		CreatedAt: heldAt, PolicyRule: "wire_high_value", Explanation: "Wire transfer exceeds $10,000.",
		Payload: []byte(`{"arguments":{"amount":18250,"beneficiary":"Kestrel Components Pte"}}`),
	}
}

func TestWorker_NotifiesEachChannelOncePerHeldAction(t *testing.T) {
	entry := pending("pending")
	store := newFakeStore(entry, pending("approved"))
	slack, hook := &recordingChannel{name: "slack"}, &recordingChannel{name: "webhook"}
	w := NewWorker(store, []Channel{slack, hook}, "https://console.corp.test/", zap.NewNop())

	w.ProcessOnce(context.Background())
	w.ProcessOnce(context.Background())

	require.Len(t, slack.actions, 1, "only the pending action, and only once")
	require.Len(t, hook.actions, 1)
	got := slack.actions[0]
	assert.Equal(t, entry.ID.String(), got.ID)
	assert.Equal(t, "wire_high_value", got.Rule)
	assert.Equal(t, "https://console.corp.test/#inbox", got.ReviewURL)
	encoded, _ := json.Marshal(got)
	assert.NotContains(t, string(encoded), "Kestrel", "tool arguments never leave Elodea in a notification")
}

func TestWorker_RetriesFailuresWithBackoffAndRecordsTheError(t *testing.T) {
	entry := pending("pending")
	store := newFakeStore(entry)
	flaky := &recordingChannel{name: "webhook", err: errors.New("endpoint answered 503")}
	w := NewWorker(store, []Channel{flaky}, "", zap.NewNop())

	w.ProcessOnce(context.Background())
	row := store.outbox[[2]string{entry.ID.String(), "webhook"}]
	assert.False(t, row.delivered)
	assert.Equal(t, "endpoint answered 503", row.lastError)
	assert.True(t, row.nextAt.After(time.Now()), "the next attempt waits")

	w.ProcessOnce(context.Background())
	assert.Len(t, flaky.actions, 1, "not retried before the backoff elapses")

	row.nextAt = time.Now().Add(-time.Second)
	flaky.err = nil
	w.ProcessOnce(context.Background())
	assert.Len(t, flaky.actions, 2)
	assert.True(t, row.delivered)
}

func TestWorker_SkipsActionsReviewedBeforeSending(t *testing.T) {
	entry := pending("pending")
	store := newFakeStore(entry)
	ch := &recordingChannel{name: "slack"}
	w := NewWorker(store, []Channel{ch}, "", zap.NewNop())

	require.NoError(t, store.EnqueueHeldNotifications(context.Background(), []string{"slack"}))
	resolved := store.entries[entry.ID]
	resolved.Status = "approved"
	store.entries[entry.ID] = resolved

	w.ProcessOnce(context.Background())
	assert.Empty(t, ch.actions, "no noise about an action someone already handled")
	assert.Equal(t, 1, store.delivered, "the outbox row is closed")
}

func TestWorker_IdleWithoutChannels(t *testing.T) {
	store := newFakeStore(pending("pending"))
	NewWorker(store, nil, "", zap.NewNop()).ProcessOnce(context.Background())
	assert.Nil(t, store.enqueued)
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	assert.Equal(t, 15*time.Second, backoff(1))
	assert.Equal(t, 30*time.Second, backoff(2))
	assert.Equal(t, 2*time.Minute, backoff(4))
	assert.Equal(t, time.Hour, backoff(20))
	assert.True(t, strings.HasPrefix(truncate(strings.Repeat("x", 600), 500), "x"))
	assert.Len(t, truncate(strings.Repeat("x", 600), 500), 500)
}
