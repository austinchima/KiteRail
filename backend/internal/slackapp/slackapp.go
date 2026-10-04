// Package slackapp lets reviewers approve or deny held actions from Slack.
//
// A Slack app (not just an incoming webhook) posts each held action to a
// reviewer channel with Approve and Deny buttons. When someone clicks, Slack
// calls Elodea's interactivity endpoint; Elodea then:
//
//  1. verifies the request really came from Slack (signing secret, HMAC over
//     the timestamp and raw body, five-minute replay window) and from the
//     configured workspace;
//  2. resolves the clicking Slack user to the email Slack has on file, and
//     accepts the click only if that email is on the configured reviewer
//     list (a Slack account alone grants nothing);
//  3. applies the decision through the same code path as the console, so it
//     is conflict-safe and recorded in the audit ledger under that email;
//  4. replaces the buttons in the message with the outcome.
//
// The Slack message never carries tool arguments; reviewers who need them
// open the action in the console.
package slackapp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/notify"
	"github.com/austinchima/kiterail/internal/quarantine"
)

const (
	actionApprove = "elodea_approve"
	actionDeny    = "elodea_deny"

	// maxSignatureAge is Slack's recommended replay window.
	maxSignatureAge = 5 * time.Minute
	// maxBody bounds an interaction payload; real payloads are a few KB.
	maxBody = 256 << 10
	// emailCacheTTL bounds how long a Slack user's email is trusted without
	// asking Slack again (an account can be deactivated or changed).
	emailCacheTTL = 10 * time.Minute

	defaultAPIBase = "https://slack.com/api"
)

// Decider applies a reviewer decision; *quarantine.Handler implements it.
type Decider interface {
	Approve(ctx context.Context, id, reviewerID string) error
	Deny(ctx context.Context, id, reviewerID, reason string) error
}

// Config is the Slack app configuration.
type Config struct {
	BotToken      string
	SigningSecret string
	ChannelID     string
	// TeamID, when set, rejects interactions from any other workspace.
	TeamID string
	// Reviewers lists the emails allowed to decide from Slack.
	Reviewers []string
	// ConsoleURL, when set, adds an "Open in console" link.
	ConsoleURL string
	// APIBase overrides the Slack Web API base URL, for GovSlack
	// (https://slack-gov.com/api). Empty means https://slack.com/api.
	APIBase string
}

// App is both a notify.Channel (posting held actions) and the HTTP handler
// for Slack's interactivity requests.
type App struct {
	cfg       Config
	reviewers map[string]bool
	decider   Decider
	logger    *zap.Logger
	client    *http.Client
	apiBase   string
	now       func() time.Time
	async     func(func()) // how response_url updates run; tests make it synchronous
	// responseURLOK limits where message updates may be posted.
	responseURLOK func(*url.URL) bool

	mu     sync.Mutex
	emails map[string]cachedEmail
}

type cachedEmail struct {
	email   string
	expires time.Time
}

// New builds the Slack app.
func New(cfg Config, decider Decider, logger *zap.Logger) *App {
	reviewers := make(map[string]bool, len(cfg.Reviewers))
	for _, r := range cfg.Reviewers {
		if r = strings.ToLower(strings.TrimSpace(r)); r != "" {
			reviewers[r] = true
		}
	}
	apiBase := strings.TrimRight(cfg.APIBase, "/")
	if apiBase == "" {
		apiBase = defaultAPIBase
	}
	return &App{
		cfg: cfg, reviewers: reviewers, decider: decider, logger: logger,
		client: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		apiBase:       apiBase,
		now:           time.Now,
		async:         func(f func()) { go f() },
		responseURLOK: slackHost,
		emails:        map[string]cachedEmail{},
	}
}

// Name implements notify.Channel.
func (*App) Name() string { return "slack_app" }

// Send implements notify.Channel: it posts the held action with buttons.
func (a *App) Send(ctx context.Context, action notify.HeldAction) error {
	body, err := json.Marshal(map[string]any{
		"channel": a.cfg.ChannelID,
		"text":    fmt.Sprintf("%s wants to run %s. Held by %s.", escape(action.Agent), escape(action.Tool), escape(action.Rule)),
		"blocks":  a.heldBlocks(action),
	})
	if err != nil {
		return err
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := a.callAPI(ctx, "chat.postMessage", body, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("slack chat.postMessage: %s", resp.Error)
	}
	return nil
}

func (a *App) heldBlocks(action notify.HeldAction) []map[string]any {
	blocks := []map[string]any{
		section(":hourglass: *An agent action is waiting for review*"),
		section(fmt.Sprintf("*Agent*\n%s\n*Tool*\n`%s`\n*Rule*\n`%s`", escape(action.Agent), escape(action.Tool), escape(action.Rule))),
	}
	if action.Explanation != "" {
		blocks = append(blocks, section(escape(action.Explanation)))
	}
	elements := []map[string]any{
		{"type": "button", "action_id": actionApprove, "style": "primary", "value": action.ID,
			"text": plain("Approve"),
			"confirm": map[string]any{
				"title": plain("Approve this action?"), "confirm": plain("Approve"), "deny": plain("Cancel"),
				"text": plain("It will run once, after Elodea re-checks current policy."),
			}},
		{"type": "button", "action_id": actionDeny, "style": "danger", "value": action.ID, "text": plain("Deny")},
	}
	if action.ReviewURL != "" {
		elements = append(elements, map[string]any{"type": "button", "action_id": "elodea_open", "url": action.ReviewURL, "text": plain("Open in console")})
	}
	blocks = append(blocks,
		map[string]any{"type": "actions", "block_id": "elodea_decision", "elements": elements},
		contextBlock("Held "+action.HeldAt.UTC().Format("2006-01-02 15:04 MST")+" · "+action.ID),
	)
	return blocks
}

// interaction is the subset of Slack's block_actions payload Elodea reads.
type interaction struct {
	Type string `json:"type"`
	Team struct {
		ID string `json:"id"`
	} `json:"team"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
	ResponseURL string `json:"response_url"`
	Actions     []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
	} `json:"actions"`
	Message struct {
		Blocks []json.RawMessage `json:"blocks"`
	} `json:"message"`
}

// ServeHTTP handles Slack's interactivity requests.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !a.verify(r.Header.Get("X-Slack-Request-Timestamp"), r.Header.Get("X-Slack-Signature"), raw) {
		a.logger.Warn("rejected Slack interaction with an invalid signature")
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var in interaction
	if err := json.Unmarshal([]byte(form.Get("payload")), &in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if a.cfg.TeamID != "" && in.Team.ID != a.cfg.TeamID {
		a.logger.Warn("rejected Slack interaction from another workspace", zap.String("team", in.Team.ID))
		http.Error(w, "unknown workspace", http.StatusForbidden)
		return
	}
	if in.Type != "block_actions" || len(in.Actions) == 0 {
		w.WriteHeader(http.StatusOK) // not ours to act on; acknowledge so Slack doesn't retry
		return
	}
	act := in.Actions[0]
	if act.ActionID != actionApprove && act.ActionID != actionDeny {
		w.WriteHeader(http.StatusOK) // e.g. the "Open in console" link button
		return
	}

	// Slack expects an answer within three seconds. The decision is a few
	// quick database writes, so it runs now; the message update follows.
	outcome := a.decide(r.Context(), in.User.ID, act.ActionID, act.Value)
	w.WriteHeader(http.StatusOK)
	if in.ResponseURL != "" {
		blocks := a.resolvedBlocks(in.Message.Blocks, outcome)
		a.async(func() { a.respond(in.ResponseURL, outcome, blocks) })
	}
}

// outcome is what happened, phrased for the Slack thread.
type outcome struct {
	text     string
	resolved bool // true replaces the buttons; false leaves them for someone else
}

func (a *App) decide(ctx context.Context, slackUser, actionID, id string) outcome {
	email, err := a.email(ctx, slackUser)
	if err != nil {
		a.logger.Warn("could not resolve Slack user", zap.String("slack_user", slackUser), zap.Error(err))
		return outcome{text: ":warning: Elodea couldn't confirm who you are in Slack, so nothing was changed. Try again, or use the console."}
	}
	if !a.reviewers[email] {
		a.logger.Warn("Slack user is not an Elodea reviewer", zap.String("email", email))
		return outcome{text: fmt.Sprintf(":no_entry: %s isn't on Elodea's reviewer list, so nothing was changed.", escape(email))}
	}
	verb := "approved"
	if actionID == actionApprove {
		err = a.decider.Approve(ctx, id, email)
	} else {
		verb = "denied"
		err = a.decider.Deny(ctx, id, email, "Denied in Slack")
	}
	switch {
	case err == nil:
		a.logger.Info("held action decided in Slack", zap.String("id", id), zap.String("decision", verb), zap.String("identity", email))
		if verb == "approved" {
			return outcome{text: fmt.Sprintf(":white_check_mark: Approved by %s. Elodea re-checks current policy, then runs it once.", escape(email)), resolved: true}
		}
		return outcome{text: fmt.Sprintf(":x: Denied by %s. It will not run.", escape(email)), resolved: true}
	case errors.Is(err, quarantine.ErrAlreadyResolved):
		return outcome{text: ":information_source: Someone already decided this action. See the console for who and when.", resolved: true}
	case errors.Is(err, quarantine.ErrNotFound):
		return outcome{text: ":information_source: This action no longer exists.", resolved: true}
	case errors.Is(err, quarantine.ErrAuditUnavailable):
		return outcome{text: fmt.Sprintf(":warning: Your decision (%s) was saved, but the audit log was unavailable. Tell your Elodea operator.", verb), resolved: true}
	default:
		a.logger.Error("Slack decision failed", zap.String("id", id), zap.Error(err))
		return outcome{text: ":warning: Elodea couldn't record that decision. Nothing was changed; try again or use the console."}
	}
}

// resolvedBlocks keeps the original message and swaps the buttons for the
// outcome once the action is decided.
func (a *App) resolvedBlocks(original []json.RawMessage, o outcome) []any {
	blocks := make([]any, 0, len(original)+1)
	for _, b := range original {
		var probe struct {
			BlockID string `json:"block_id"`
		}
		if o.resolved && json.Unmarshal(b, &probe) == nil && probe.BlockID == "elodea_decision" {
			continue
		}
		blocks = append(blocks, b)
	}
	return append(blocks, section(o.text))
}

func (a *App) respond(responseURL string, o outcome, blocks []any) {
	// response_url is inside the signed payload, but it is still only ever
	// allowed to point at Slack.
	u, err := url.Parse(responseURL)
	if err != nil || !a.responseURLOK(u) {
		a.logger.Warn("ignored a Slack response_url outside slack.com", zap.String("url", responseURL))
		return
	}
	payload := map[string]any{"text": o.text, "replace_original": o.resolved, "blocks": blocks}
	if !o.resolved {
		payload = map[string]any{"text": o.text, "replace_original": false, "response_type": "ephemeral"}
	}
	body, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		a.logger.Warn("failed to update the Slack message", zap.Error(err))
		return
	}
	_ = resp.Body.Close()
}

// verify checks Slack's request signature: v0=HMAC-SHA256(secret, "v0:<ts>:<body>").
func (a *App) verify(timestamp, signature string, body []byte) bool {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || a.cfg.SigningSecret == "" {
		return false
	}
	if age := a.now().Sub(time.Unix(ts, 0)); age > maxSignatureAge || age < -maxSignatureAge {
		return false
	}
	return hmac.Equal([]byte(Sign(a.cfg.SigningSecret, timestamp, body)), []byte(signature))
}

// Sign computes Slack's v0 request signature (exported for tests and tools).
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + timestamp + ":"))
	mac.Write(body)
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

// email returns the email Slack holds for a user, refusing bots and
// deactivated accounts. Results are cached briefly.
func (a *App) email(ctx context.Context, userID string) (string, error) {
	if userID == "" {
		return "", errors.New("no user in payload")
	}
	a.mu.Lock()
	if c, ok := a.emails[userID]; ok && a.now().Before(c.expires) {
		a.mu.Unlock()
		return c.email, nil
	}
	a.mu.Unlock()

	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		User  struct {
			Deleted bool `json:"deleted"`
			IsBot   bool `json:"is_bot"`
			Profile struct {
				Email string `json:"email"`
			} `json:"profile"`
		} `json:"user"`
	}
	if err := a.callAPI(ctx, "users.info?user="+url.QueryEscape(userID), nil, &resp); err != nil {
		return "", err
	}
	switch {
	case !resp.OK:
		return "", fmt.Errorf("slack users.info: %s", resp.Error)
	case resp.User.Deleted || resp.User.IsBot:
		return "", errors.New("deactivated or bot account")
	case resp.User.Profile.Email == "":
		return "", errors.New("no email on the Slack profile (does the app have users:read.email?)")
	}
	email := strings.ToLower(resp.User.Profile.Email)
	a.mu.Lock()
	a.emails[userID] = cachedEmail{email: email, expires: a.now().Add(emailCacheTTL)}
	a.mu.Unlock()
	return email, nil
}

// callAPI calls a Slack Web API method: POST JSON when body is set, GET otherwise.
func (a *App) callAPI(ctx context.Context, method string, body []byte, out any) error {
	verb, reader := http.MethodGet, io.Reader(nil)
	if body != nil {
		verb, reader = http.MethodPost, bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, verb, a.apiBase+"/"+method, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.BotToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack %s answered %d", strings.SplitN(method, "?", 2)[0], resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// slackHost accepts only HTTPS URLs on Slack's own domains (including GovSlack).
func slackHost(u *url.URL) bool {
	if u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	for _, domain := range []string{"slack.com", "slack-gov.com"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func section(text string) map[string]any {
	return map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": text}}
}

func contextBlock(text string) map[string]any {
	return map[string]any{"type": "context", "elements": []map[string]any{{"type": "mrkdwn", "text": text}}}
}

func plain(text string) map[string]any { return map[string]any{"type": "plain_text", "text": text} }

// escape neutralises Slack's control characters so agent-chosen text cannot
// inject links or mentions.
func escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
