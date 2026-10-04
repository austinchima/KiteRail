package slackapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/austinchima/elodea/internal/notify"
	"github.com/austinchima/elodea/internal/quarantine"
)

const (
	secret = "8f742231b10e8888abcd99yyyzzz85a5"
	team   = "T0ELODEA"
	heldID = "7ab69ae4-dc75-4cd4-bff9-430f88b14c35"
)

// fakeSlack serves users.info and chat.postMessage and records what it got.
type fakeSlack struct {
	mu          sync.Mutex
	server      *httptest.Server
	users       map[string]map[string]any
	userLookups int
	posts       []map[string]any
	postOK      bool
	responses   []map[string]any // what was posted to response_url
	authHeaders []string
}

func newFakeSlack(t *testing.T) *fakeSlack {
	f := &fakeSlack{postOK: true, users: map[string]map[string]any{
		"U_PRIYA": {"profile": map[string]any{"email": "Priya.Raman@corp.test"}},
		"U_SAM":   {"profile": map[string]any{"email": "sam@corp.test"}},
		"U_BOT":   {"is_bot": true, "profile": map[string]any{"email": "bot@corp.test"}},
		"U_GONE":  {"deleted": true, "profile": map[string]any{"email": "priya.raman@corp.test"}},
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/users.info", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.userLookups++
		f.authHeaders = append(f.authHeaders, r.Header.Get("Authorization"))
		user, ok := f.users[r.URL.Query().Get("user")]
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "user_not_found"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "user": user})
	})
	mux.HandleFunc("POST /api/chat.postMessage", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.posts = append(f.posts, body)
		f.authHeaders = append(f.authHeaders, r.Header.Get("Authorization"))
		if !f.postOK {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "channel_not_found"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /response", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.responses = append(f.responses, body)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

type fakeDecider struct {
	mu        sync.Mutex
	approvals []string
	denials   []string
	err       error
}

func (d *fakeDecider) Approve(_ context.Context, id, who string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.approvals = append(d.approvals, id+" by "+who)
	return d.err
}

func (d *fakeDecider) Deny(_ context.Context, id, who, reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.denials = append(d.denials, id+" by "+who+": "+reason)
	return d.err
}

func newTestApp(t *testing.T, slack *fakeSlack, decider Decider) *App {
	app := New(Config{
		BotToken: "xoxb-test", SigningSecret: secret, ChannelID: "C0REVIEW", TeamID: team,
		Reviewers: []string{"priya.raman@corp.test"}, APIBase: slack.server.URL + "/api",
	}, decider, zap.NewNop())
	app.async = func(f func()) { f() }
	app.responseURLOK = func(u *url.URL) bool { return strings.HasPrefix(u.String(), slack.server.URL) }
	return app
}

// click builds a signed block_actions request as Slack would send it.
func click(t *testing.T, slack *fakeSlack, user, actionID, teamID string, signedAt time.Time) *http.Request {
	payload, err := json.Marshal(map[string]any{
		"type": "block_actions", "team": map[string]any{"id": teamID}, "user": map[string]any{"id": user},
		"response_url": slack.server.URL + "/response",
		"actions":      []map[string]any{{"action_id": actionID, "value": heldID}},
		"message": map[string]any{"blocks": []map[string]any{
			{"type": "section", "block_id": "summary", "text": map[string]any{"type": "mrkdwn", "text": "held"}},
			{"type": "actions", "block_id": "elodea_decision"},
		}},
	})
	require.NoError(t, err)
	body := "payload=" + url.QueryEscape(string(payload))
	ts := strconv.FormatInt(signedAt.Unix(), 10)
	req := httptest.NewRequest(http.MethodPost, "/integrations/slack/interactions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", Sign(secret, ts, []byte(body)))
	return req
}

func serve(app *App, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestSend_PostsHeldActionWithButtonsAndNoArguments(t *testing.T) {
	slack := newFakeSlack(t)
	app := newTestApp(t, slack, &fakeDecider{})
	action := notify.HeldAction{
		ID: heldID, Agent: "treasury-agent", Tool: "<!channel> swift.wire", Rule: "wire_high_value",
		Explanation: "Wire exceeds $10,000.", HeldAt: time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC),
		ReviewURL: "https://console.corp.test/#inbox",
	}
	require.NoError(t, app.Send(context.Background(), action))

	require.Len(t, slack.posts, 1)
	post := slack.posts[0]
	assert.Equal(t, "C0REVIEW", post["channel"])
	assert.Equal(t, "Bearer xoxb-test", slack.authHeaders[0])
	text := fmt.Sprint(post)
	assert.Contains(t, text, actionApprove)
	assert.Contains(t, text, actionDeny)
	assert.Contains(t, text, heldID, "buttons carry the held action's ID")
	assert.Contains(t, text, "https://console.corp.test/#inbox")
	assert.Contains(t, text, "&lt;!channel&gt;", "agent-supplied text cannot @-mention the channel")
	assert.NotContains(t, text, "<!channel>")

	slack.postOK = false
	assert.ErrorContains(t, app.Send(context.Background(), action), "channel_not_found")
}

func TestApprove_FromAReviewerRecordsTheirEmailAndUpdatesTheMessage(t *testing.T) {
	slack := newFakeSlack(t)
	decider := &fakeDecider{}
	app := newTestApp(t, slack, decider)

	rec := serve(app, click(t, slack, "U_PRIYA", actionApprove, team, time.Now()))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{heldID + " by priya.raman@corp.test"}, decider.approvals)

	require.Len(t, slack.responses, 1)
	resp := slack.responses[0]
	assert.Equal(t, true, resp["replace_original"])
	assert.Contains(t, resp["text"], "Approved by priya.raman@corp.test")
	blocks := fmt.Sprint(resp["blocks"])
	assert.NotContains(t, blocks, "elodea_decision", "the buttons are removed once decided")
	assert.Contains(t, blocks, "summary", "the rest of the message is kept")
}

func TestDeny_RecordsAReason(t *testing.T) {
	slack := newFakeSlack(t)
	decider := &fakeDecider{}
	app := newTestApp(t, slack, decider)
	serve(app, click(t, slack, "U_PRIYA", actionDeny, team, time.Now()))
	assert.Equal(t, []string{heldID + " by priya.raman@corp.test: Denied in Slack"}, decider.denials)
	assert.Contains(t, slack.responses[0]["text"], "Denied by priya.raman@corp.test")
}

func TestForgedOrReplayedRequestsAreRejected(t *testing.T) {
	slack := newFakeSlack(t)
	decider := &fakeDecider{}
	app := newTestApp(t, slack, decider)

	tampered := click(t, slack, "U_PRIYA", actionApprove, team, time.Now())
	tampered.Header.Set("X-Slack-Signature", "v0=deadbeef")
	assert.Equal(t, http.StatusUnauthorized, serve(app, tampered).Code)

	stale := click(t, slack, "U_PRIYA", actionApprove, team, time.Now().Add(-6*time.Minute))
	assert.Equal(t, http.StatusUnauthorized, serve(app, stale).Code, "a captured request cannot be replayed later")

	otherTeam := click(t, slack, "U_PRIYA", actionApprove, "T0ATTACKER", time.Now())
	assert.Equal(t, http.StatusForbidden, serve(app, otherTeam).Code)

	unsigned := click(t, slack, "U_PRIYA", actionApprove, team, time.Now())
	unsigned.Header.Del("X-Slack-Signature")
	assert.Equal(t, http.StatusUnauthorized, serve(app, unsigned).Code)

	assert.Empty(t, decider.approvals, "nothing was approved")
}

func TestOnlyListedLiveHumansCanDecide(t *testing.T) {
	for _, user := range []string{"U_SAM", "U_BOT", "U_GONE", "U_UNKNOWN"} {
		t.Run(user, func(t *testing.T) {
			slack := newFakeSlack(t)
			decider := &fakeDecider{}
			app := newTestApp(t, slack, decider)

			rec := serve(app, click(t, slack, user, actionApprove, team, time.Now()))
			assert.Equal(t, http.StatusOK, rec.Code, "Slack still gets an acknowledgement")
			assert.Empty(t, decider.approvals)
			require.Len(t, slack.responses, 1)
			assert.Equal(t, false, slack.responses[0]["replace_original"], "the buttons stay for a real reviewer")
			assert.Equal(t, "ephemeral", slack.responses[0]["response_type"], "only the clicker sees the refusal")
		})
	}
}

func TestDecisionOutcomesAreExplained(t *testing.T) {
	cases := map[string]struct {
		err      error
		text     string
		resolved bool
	}{
		"already decided": {quarantine.ErrAlreadyResolved, "already decided", true},
		"gone":            {quarantine.ErrNotFound, "no longer exists", true},
		"audit down":      {quarantine.ErrAuditUnavailable, "audit log was unavailable", true},
		"database down":   {errors.New("connection refused"), "couldn't record that decision", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			slack := newFakeSlack(t)
			app := newTestApp(t, slack, &fakeDecider{err: tc.err})
			serve(app, click(t, slack, "U_PRIYA", actionApprove, team, time.Now()))
			require.Len(t, slack.responses, 1)
			assert.Contains(t, slack.responses[0]["text"], tc.text)
			assert.Equal(t, tc.resolved, slack.responses[0]["replace_original"])
		})
	}
}

func TestUserEmailsAreCachedBriefly(t *testing.T) {
	slack := newFakeSlack(t)
	app := newTestApp(t, slack, &fakeDecider{})
	now := time.Now()
	app.now = func() time.Time { return now }

	serve(app, click(t, slack, "U_PRIYA", actionApprove, team, now))
	serve(app, click(t, slack, "U_PRIYA", actionApprove, team, now))
	assert.Equal(t, 1, slack.userLookups)

	now = now.Add(emailCacheTTL + time.Second)
	serve(app, click(t, slack, "U_PRIYA", actionApprove, team, now))
	assert.Equal(t, 2, slack.userLookups, "a deactivated account stops working within the cache window")
}

func TestOtherInteractionsAreAcknowledgedAndIgnored(t *testing.T) {
	slack := newFakeSlack(t)
	decider := &fakeDecider{}
	app := newTestApp(t, slack, decider)
	assert.Equal(t, http.StatusOK, serve(app, click(t, slack, "U_PRIYA", "elodea_open", team, time.Now())).Code)
	assert.Empty(t, decider.approvals)
	assert.Equal(t, http.StatusMethodNotAllowed, serve(app, httptest.NewRequest(http.MethodGet, "/", nil)).Code)
}

func TestResponseURLMustBeSlack(t *testing.T) {
	assert.True(t, slackHost(mustParse("https://hooks.slack.com/actions/T/1/x")))
	assert.True(t, slackHost(mustParse("https://hooks.slack-gov.com/actions/T/1/x")))
	assert.False(t, slackHost(mustParse("http://hooks.slack.com/actions")), "https only")
	assert.False(t, slackHost(mustParse("https://slack.com.evil.test/x")))
	assert.False(t, slackHost(mustParse("https://evilslack.com/x")))

	// With the real check in place, a non-Slack response_url gets no request.
	slack := newFakeSlack(t)
	app := newTestApp(t, slack, &fakeDecider{})
	app.responseURLOK = slackHost
	serve(app, click(t, slack, "U_PRIYA", actionApprove, team, time.Now()))
	assert.Empty(t, slack.responses)
}

func mustParse(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
