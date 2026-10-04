// Package notify tells reviewers when an action is held for review, so a
// waiting agent is not stuck until someone happens to open the console.
//
// Delivery runs through a Postgres outbox (notification_outbox): each tick
// queues every pending held action for every configured channel, then sends
// what is due. Rows are claimed with FOR UPDATE SKIP LOCKED, so replicas never
// send the same notification twice concurrently; a failed send is retried
// with backoff, and a crash mid-send is retried after the lease expires.
// Delivery is therefore at-least-once: receivers should deduplicate on the
// held action's ID (the webhook's X-Elodea-Delivery header).
//
// Notifications carry who, what tool, and why it was held, plus a link to
// review it. They never carry the tool arguments, which can hold payment or
// personal data that does not belong in a chat channel.
package notify

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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/austinchima/elodea/internal/db"
	"github.com/austinchima/elodea/internal/metrics"
)

// HeldAction is what a notification describes.
type HeldAction struct {
	ID          string    `json:"id"`
	Agent       string    `json:"agent"`
	Tool        string    `json:"tool"`
	Rule        string    `json:"rule"`
	Explanation string    `json:"explanation"`
	HeldAt      time.Time `json:"held_at"`
	ReviewURL   string    `json:"review_url,omitempty"`
}

// Channel delivers one notification. Send must be safe to call again for the
// same action: delivery is at-least-once.
type Channel interface {
	Name() string
	Send(ctx context.Context, action HeldAction) error
}

// newHTTPClient never follows redirects: a webhook endpoint that redirects
// could otherwise steer Elodea's requests somewhere the operator never chose.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func post(ctx context.Context, client *http.Client, url string, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Elodea-Notifier/1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("endpoint answered %d", resp.StatusCode)
	}
	return nil
}

// Slack posts to a Slack incoming webhook.
type Slack struct {
	url    string
	client *http.Client
}

// NewSlack returns a Slack channel for an incoming-webhook URL.
func NewSlack(webhookURL string) *Slack { return &Slack{url: webhookURL, client: newHTTPClient()} }

func (*Slack) Name() string { return "slack" }

func (s *Slack) Send(ctx context.Context, a HeldAction) error {
	summary := fmt.Sprintf("%s wants to run %s. Held by %s.", slackEscape(a.Agent), slackEscape(a.Tool), slackEscape(a.Rule))
	fields := fmt.Sprintf("*Agent*\n%s\n*Tool*\n`%s`\n*Rule*\n`%s`", slackEscape(a.Agent), slackEscape(a.Tool), slackEscape(a.Rule))
	blocks := []map[string]any{
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": ":hourglass: *An agent action is waiting for review*"}},
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": fields}},
	}
	if a.Explanation != "" {
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": slackEscape(a.Explanation)}})
	}
	if a.ReviewURL != "" {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []map[string]any{{
			"type": "button", "style": "primary", "url": a.ReviewURL,
			"text": map[string]any{"type": "plain_text", "text": "Review in Elodea"},
		}}})
	}
	blocks = append(blocks, map[string]any{"type": "context", "elements": []map[string]any{{
		"type": "mrkdwn", "text": "Held " + a.HeldAt.UTC().Format("2006-01-02 15:04 MST") + " · " + a.ID,
	}}})
	body, err := json.Marshal(map[string]any{"text": summary, "blocks": blocks})
	if err != nil {
		return err
	}
	return post(ctx, s.client, s.url, body, nil)
}

// slackEscape neutralises Slack's control characters so an agent-chosen tool
// name cannot inject links or mentions into the message.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// Webhook posts a signed JSON event to any HTTPS endpoint (PagerDuty,
// Opsgenie, ServiceNow, Teams workflows, or the customer's own service).
type Webhook struct {
	url    string
	secret []byte
	client *http.Client
	now    func() time.Time
}

// NewWebhook returns a webhook channel. With a secret, every request carries
// X-Elodea-Signature: sha256=HMAC(secret, "<timestamp>.<body>").
func NewWebhook(url, secret string) *Webhook {
	return &Webhook{url: url, secret: []byte(secret), client: newHTTPClient(), now: time.Now}
}

func (*Webhook) Name() string { return "webhook" }

// EventHeld is the webhook event type for a newly held action.
const EventHeld = "action.held"

func (w *Webhook) Send(ctx context.Context, a HeldAction) error {
	body, err := json.Marshal(struct {
		Type   string     `json:"type"`
		Action HeldAction `json:"action"`
	}{EventHeld, a})
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(w.now().Unix(), 10)
	headers := map[string]string{
		"X-Elodea-Event":     EventHeld,
		"X-Elodea-Delivery":  a.ID,
		"X-Elodea-Timestamp": ts,
	}
	if len(w.secret) > 0 {
		headers["X-Elodea-Signature"] = Sign(w.secret, ts, body)
	}
	return post(ctx, w.client, w.url, body, headers)
}

// Sign computes the webhook signature header value. Receivers recompute it
// over the raw body and reject requests whose timestamp is more than a few
// minutes old, which stops replays of a captured request.
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Store is the persistence the worker needs; *db.Queries implements it.
type Store interface {
	EnqueueHeldNotifications(ctx context.Context, channels []string) error
	ClaimDueNotifications(ctx context.Context, arg db.ClaimDueNotificationsParams) ([]db.ClaimDueNotificationsRow, error)
	MarkNotificationDelivered(ctx context.Context, arg db.MarkNotificationDeliveredParams) error
	MarkNotificationFailed(ctx context.Context, arg db.MarkNotificationFailedParams) error
	GetQuarantineEntry(ctx context.Context, id uuid.UUID) (db.Quarantine, error)
}

const (
	// maxAttempts bounds retries: about 2.5 hours of backoff in total.
	maxAttempts = 8
	batchSize   = 25
)

// Worker drains the notification outbox.
type Worker struct {
	store      Store
	channels   map[string]Channel
	names      []string
	consoleURL string
	interval   time.Duration
	logger     *zap.Logger
	now        func() time.Time
}

// NewWorker builds a worker for the given channels. consoleURL, when set,
// makes every notification link straight to the approvals queue.
func NewWorker(store Store, channels []Channel, consoleURL string, logger *zap.Logger) *Worker {
	w := &Worker{
		store: store, channels: map[string]Channel{}, consoleURL: strings.TrimRight(consoleURL, "/"),
		interval: 5 * time.Second, logger: logger, now: time.Now,
	}
	for _, c := range channels {
		w.channels[c.Name()] = c
		w.names = append(w.names, c.Name())
	}
	return w
}

// Run processes the outbox until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		w.ProcessOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// ProcessOnce queues new held actions and sends everything due.
func (w *Worker) ProcessOnce(ctx context.Context) {
	if len(w.names) == 0 {
		return
	}
	if err := w.store.EnqueueHeldNotifications(ctx, w.names); err != nil {
		w.logger.Warn("failed to queue held-action notifications", zap.Error(err))
		return
	}
	due, err := w.store.ClaimDueNotifications(ctx, db.ClaimDueNotificationsParams{MaxAttempts: maxAttempts, BatchSize: batchSize})
	if err != nil {
		w.logger.Warn("failed to claim notifications", zap.Error(err))
		return
	}
	for _, row := range due {
		w.deliver(ctx, row)
	}
}

func (w *Worker) deliver(ctx context.Context, row db.ClaimDueNotificationsRow) {
	id, err := uuid.Parse(row.QuarantineID)
	if err != nil {
		return
	}
	key := db.MarkNotificationDeliveredParams{QuarantineID: id, Channel: row.Channel}
	channel, ok := w.channels[row.Channel]
	if !ok {
		// A channel removed from configuration: nothing will ever send it.
		w.markDelivered(ctx, key, row.Channel, "skipped")
		return
	}
	entry, err := w.store.GetQuarantineEntry(ctx, id)
	if err != nil {
		w.fail(ctx, key, row.Attempts, fmt.Errorf("read held action: %w", err))
		return
	}
	if entry.Status != "pending" {
		// Reviewed before we got to it: a notification now would only be noise.
		w.markDelivered(ctx, key, row.Channel, "skipped")
		return
	}
	action := HeldAction{
		ID: row.QuarantineID, Agent: entry.AgentID, Tool: entry.ToolName,
		Rule: entry.PolicyRule, Explanation: entry.Explanation, HeldAt: entry.CreatedAt,
	}
	if w.consoleURL != "" {
		action.ReviewURL = w.consoleURL + "/#inbox"
	}
	if err := channel.Send(ctx, action); err != nil {
		w.fail(ctx, key, row.Attempts, err)
		return
	}
	w.markDelivered(ctx, key, row.Channel, "delivered")
}

func (w *Worker) markDelivered(ctx context.Context, key db.MarkNotificationDeliveredParams, channel, outcome string) {
	if err := w.store.MarkNotificationDelivered(ctx, key); err != nil {
		w.logger.Warn("failed to record notification delivery", zap.String("channel", channel), zap.Error(err))
	}
	metrics.NotificationsTotal.WithLabelValues(channel, outcome).Inc()
}

func (w *Worker) fail(ctx context.Context, key db.MarkNotificationDeliveredParams, attempts int32, cause error) {
	outcome := "retrying"
	if attempts >= maxAttempts {
		outcome = "gave_up"
		w.logger.Error("giving up on held-action notification", zap.String("channel", key.Channel), zap.String("id", key.QuarantineID.String()), zap.Error(cause))
	} else {
		w.logger.Warn("held-action notification failed, will retry", zap.String("channel", key.Channel), zap.String("id", key.QuarantineID.String()), zap.Int32("attempt", attempts), zap.Error(cause))
	}
	metrics.NotificationsTotal.WithLabelValues(key.Channel, outcome).Inc()
	if err := w.store.MarkNotificationFailed(ctx, db.MarkNotificationFailedParams{
		NextAttemptAt: w.now().Add(backoff(attempts)), LastError: truncate(cause.Error(), 500),
		QuarantineID: key.QuarantineID, Channel: key.Channel,
	}); err != nil && !errors.Is(err, context.Canceled) {
		w.logger.Warn("failed to record notification failure", zap.Error(err))
	}
}

// backoff is 15s, 30s, 1m, 2m … capped at one hour.
func backoff(attempts int32) time.Duration {
	d := 15 * time.Second << max(attempts-1, 0)
	return min(d, time.Hour)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
