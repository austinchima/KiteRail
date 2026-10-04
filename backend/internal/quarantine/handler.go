package quarantine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/ledger"
)

// maxDenyBodyBytes caps the deny-request body: the payload carries only a
// human-readable reason string, so anything larger is abuse. The cap keeps a
// large body from being buffered just to be rejected.
const maxDenyBodyBytes = 1 << 10 // 1 KiB

// StoreAPI is the persistence surface used by handler/worker (mockable).
type StoreAPI interface {
	Get(ctx context.Context, id string) (db.QuarantineEntry, error)
	List(ctx context.Context, status string) ([]db.QuarantineEntry, error)
	Approve(ctx context.Context, id, approvedBy string) error
	Deny(ctx context.Context, id, deniedBy, reason string) error
	ClaimApproved(ctx context.Context, limit int) ([]db.QuarantineEntry, error)
	MarkReplayed(ctx context.Context, id string) error
	MarkReplayFailed(ctx context.Context, id string) error
	ReturnToApproved(ctx context.Context, id string) error
	RecoverStuckReplays(ctx context.Context) (int64, error)
	WithReplayLock(ctx context.Context, replay func(context.Context) error) (bool, error)
}

// Handler exposes REST endpoints for the quarantine queue.
//
// Approval/denial identity is ALWAYS derived from the authenticated
// reviewer/admin identity in the request context — never from the request
// body, which any agent could forge.
type Handler struct {
	store  StoreAPI
	lStore LedgerAppender
	logger *zap.Logger
}

// NewHandler creates a new quarantine HTTP handler.
func NewHandler(store StoreAPI, lStore *ledger.Store, logger *zap.Logger) *Handler {
	var appender LedgerAppender
	if lStore != nil {
		appender = lStore
	}
	return &Handler{
		store:  store,
		lStore: appender,
		logger: logger,
	}
}

// validStatuses are the quarantine states a list request may filter on.
var validStatuses = map[string]bool{
	StatusPending: true, StatusApproved: true, StatusReplaying: true,
	StatusReplayed: true, StatusReplayFailed: true, StatusDenied: true,
}

// payloadHash is the ledger join key between the proxy's original quarantine
// decision (which hashes the same request body) and every HITL entry after it.
func payloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// writeStoreError maps store errors to HTTP status codes. Only a genuinely
// missing item is a 404; database failures must surface as 5xx.
func (h *Handler) writeStoreError(w http.ResponseWriter, id, op string, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		http.Error(w, `{"error": "quarantine item not found"}`, http.StatusNotFound)
	case errors.Is(err, ErrAlreadyResolved):
		http.Error(w, `{"error": "quarantine item already resolved"}`, http.StatusConflict)
	default:
		h.logger.Error("quarantine store failure", zap.String("op", op), zap.String("id", id), zap.Error(err))
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
	}
}

// ServeHTTP routes quarantine API requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/quarantine")
	path = strings.TrimPrefix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		h.listPending(w, r)
	case r.Method == http.MethodGet && path != "":
		h.getEntry(w, r, path)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/approve"):
		id := strings.TrimSuffix(path, "/approve")
		h.approveEntry(w, r, id)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/deny"):
		id := strings.TrimSuffix(path, "/deny")
		h.denyEntry(w, r, id)
	default:
		http.Error(w, `{"error": "not found"}`, http.StatusNotFound)
	}
}

func (h *Handler) listPending(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = StatusPending
	}
	if !validStatuses[status] {
		http.Error(w, `{"error": "unknown status"}`, http.StatusBadRequest)
		return
	}
	entries, err := h.store.List(r.Context(), status)
	if err != nil {
		h.logger.Error("failed to list quarantine", zap.Error(err))
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(entries)
}

func (h *Handler) getEntry(w http.ResponseWriter, r *http.Request, id string) {
	entry, err := h.store.Get(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, id, "get", err)
		return
	}
	json.NewEncoder(w).Encode(entry)
}

// reviewerIdentity returns the authenticated human identity for HITL routes.
func reviewerIdentity(r *http.Request) (string, bool) {
	identity, ok := auth.FromContext(r.Context())
	if !ok || (identity.Role != auth.RoleReviewer && identity.Role != auth.RoleAdmin) {
		return "", false
	}
	return identity.ID, true
}

// ErrAuditUnavailable means the decision was committed but its ledger entry
// could not be written. Callers must not report plain success.
var ErrAuditUnavailable = errors.New("decision recorded but audit unavailable")

// Approve records reviewerID's approval of a held action and ledgers it.
// Replay is NOT performed here: the durable Worker picks the 'approved' entry
// up from Postgres and owns all retry/state transitions, so a crash after
// this returns loses nothing. reviewerID must come from an authenticated
// human identity (console session, bearer token, or a verified Slack user).
func (h *Handler) Approve(ctx context.Context, id, reviewerID string) error {
	// Fetch before marking so the ledger entry carries tool and payload context.
	entry, err := h.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := h.store.Approve(ctx, id, reviewerID); err != nil {
		return err
	}
	// Record the human decision itself. The worker's write-ahead entry still
	// guarantees the execution is ledgered, so a failure here is reported to
	// the reviewer rather than silently swallowed.
	return h.appendLedger(ctx, entry, reviewerID, "approved", "hitl_approval")
}

// Deny records reviewerID's denial of a held action and ledgers it.
func (h *Handler) Deny(ctx context.Context, id, reviewerID, reason string) error {
	entry, err := h.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := h.store.Deny(ctx, id, reviewerID, reason); err != nil {
		return err
	}
	return h.appendLedger(ctx, entry, reviewerID, "denied", "hitl_denial")
}

// writeDecisionError maps an Approve/Deny error to an HTTP response.
func (h *Handler) writeDecisionError(w http.ResponseWriter, id, op string, err error) {
	if errors.Is(err, ErrAuditUnavailable) {
		http.Error(w, `{"error": "decision recorded but audit unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	h.writeStoreError(w, id, op, err)
}

func (h *Handler) approveEntry(w http.ResponseWriter, r *http.Request, id string) {
	reviewerID, ok := reviewerIdentity(r)
	if !ok {
		http.Error(w, `{"error": "reviewer or admin role required"}`, http.StatusForbidden)
		return
	}
	if err := h.Approve(r.Context(), id, reviewerID); err != nil {
		h.writeDecisionError(w, id, "approve", err)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "approved", "id": id})
}

func (h *Handler) denyEntry(w http.ResponseWriter, r *http.Request, id string) {
	reviewerID, ok := reviewerIdentity(r)
	if !ok {
		http.Error(w, `{"error": "reviewer or admin role required"}`, http.StatusForbidden)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	// Cap the body before decoding and fail on malformed JSON. An empty body
	// is legitimate (denial without a reason), surfaced as io.EOF.
	r.Body = http.MaxBytesReader(w, r.Body, maxDenyBodyBytes)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		h.logger.Error("failed to decode deny request body", zap.String("id", id), zap.Error(err))
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}
	// A second value or trailing garbage is not part of this request. Reading
	// through EOF also enforces the size cap when a small object has large padding.
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if err := h.Deny(r.Context(), id, reviewerID, body.Reason); err != nil {
		h.writeDecisionError(w, id, "deny", err)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "denied", "id": id})
}

// appendLedger records a reviewer decision. On failure it returns
// ErrAuditUnavailable: the state change has committed, but the reviewer must
// not be told the decision succeeded while its audit record is missing.
func (h *Handler) appendLedger(ctx context.Context, entry db.QuarantineEntry, reviewerID, decision, rule string) error {
	if h.lStore == nil {
		return nil
	}
	if err := h.lStore.Append(ctx, db.LedgerEntry{
		Agent:       reviewerID,
		Tool:        entry.ToolName,
		Decision:    decision,
		PolicyRule:  rule,
		PayloadHash: payloadHash(entry.Payload),
		RequestID:   entry.ID,
	}); err != nil {
		h.logger.Error("failed to write reviewer ledger entry", zap.String("id", entry.ID), zap.String("decision", decision), zap.Error(err))
		return ErrAuditUnavailable
	}
	return nil
}
