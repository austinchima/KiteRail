package ledger

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/austinchima/elodea/internal/db"
	"go.uber.org/zap"
)

const (
	defaultPageSize = 100
	maxPageSize     = 1000
)

// Handler handles ledger HTTP requests.
type Handler struct {
	store  *Store
	logger *zap.Logger

	// fullScan admits one full-chain operation (verify or export) at a time so
	// repeated requests cannot drain the connection pool the fail-closed
	// append needs.
	fullScan atomic.Bool
}

// NewHandler creates a new ledger HTTP handler.
func NewHandler(store *Store, logger *zap.Logger) *Handler {
	return &Handler{
		store:  store,
		logger: logger,
	}
}

// ServeHTTP routes the ledger requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/verify", "/verify/":
		h.handleVerify(w, r)
	case "/head", "/head/":
		h.handleHead(w, r)
	case "/export", "/export/":
		h.handleExport(w, r)
	case "", "/":
		h.handleQuery(w, r)
	default:
		http.Error(w, `{"error": "not found"}`, http.StatusNotFound)
	}
}

// handleQuery serves a newest-first page. Filters: agent, decision, tool.
// Pagination: pass the X-Next-Before response header back as ?before=.
func (h *Handler) handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	page := PageQuery{Limit: defaultPageSize, Agent: q.Get("agent"), Decision: q.Get("decision"), Tool: q.Get("tool")}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxPageSize {
			http.Error(w, `{"error": "limit must be between 1 and 1000"}`, http.StatusBadRequest)
			return
		}
		page.Limit = n
	}
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			http.Error(w, `{"error": "before must be a positive sequence number"}`, http.StatusBadRequest)
			return
		}
		page.BeforeSeq = n
	}

	entries, err := h.store.Page(r.Context(), page)
	if err != nil {
		h.logger.Error("Failed to query ledger", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []db.LedgerEntry{}
	}
	if len(entries) == page.Limit {
		w.Header().Set("X-Next-Before", strconv.FormatInt(entries[len(entries)-1].SeqNum, 10))
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(entries); err != nil {
		h.logger.Error("Failed to encode ledger response", zap.Error(err))
	}
}

// handleHead returns the chain head so an operator can anchor it externally.
func (h *Handler) handleHead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	head, ok, err := h.store.Head(r.Context())
	if err != nil {
		h.logger.Error("Failed to read ledger head", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		json.NewEncoder(w).Encode(map[string]any{"seq_num": 0, "hash": ""})
		return
	}
	json.NewEncoder(w).Encode(head)
}

func (h *Handler) acquireFullScan(w http.ResponseWriter) bool {
	if !h.fullScan.CompareAndSwap(false, true) {
		http.Error(w, `{"error": "a ledger verification or export is already in progress"}`, http.StatusTooManyRequests)
		return false
	}
	return true
}

// handleExport streams the chain as NDJSON in sequence order, for SIEM
// ingestion and offline verification. ?after_seq= resumes an export.
func (h *Handler) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var after int64
	if v := r.URL.Query().Get("after_seq"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			http.Error(w, `{"error": "after_seq must be a non-negative sequence number"}`, http.StatusBadRequest)
			return
		}
		after = n
	}
	if !h.acquireFullScan(w) {
		return
	}
	defer h.fullScan.Store(false)

	w.Header().Set("Content-Type", "application/x-ndjson")
	encoder := json.NewEncoder(w)
	flusher, _ := w.(http.Flusher)
	var n int
	err := h.store.Stream(r.Context(), after, func(entry db.LedgerEntry) error {
		if err := encoder.Encode(entry); err != nil {
			return err
		}
		if n++; flusher != nil && n%500 == 0 {
			flusher.Flush()
		}
		return nil
	})
	if err != nil {
		// Headers are already sent; the truncated stream plus the log is the
		// signal. Consumers resume with after_seq from their last line.
		h.logger.Error("Ledger export interrupted", zap.Error(err))
	}
}

// handleVerify recomputes the chain. Optional anchor: ?anchor_seq=&anchor_hash=
// (GET) or a JSON body {"seq_num":..,"hash":".."} (POST).
func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	anchor, err := parseAnchor(r)
	if err != nil {
		http.Error(w, `{"error": "invalid anchor"}`, http.StatusBadRequest)
		return
	}
	if !h.acquireFullScan(w) {
		return
	}
	defer h.fullScan.Store(false)

	report, err := h.store.VerifyChain(r.Context(), anchor)
	if err != nil {
		h.logger.Error("Failed to verify ledger", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !report.Valid {
		h.logger.Error("Ledger verification FAILED",
			zap.Int64("first_invalid_seq", report.FirstInvalidSeq), zap.String("reason", report.Reason))
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		h.logger.Error("Failed to encode verify response", zap.Error(err))
	}
}

func parseAnchor(r *http.Request) (*Anchor, error) {
	if r.Method == http.MethodPost && r.ContentLength != 0 {
		var a Anchor
		r.Body = http.MaxBytesReader(nil, r.Body, 1<<10)
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			return nil, err
		}
		if a.SeqNum == 0 && a.Hash == "" {
			return nil, nil
		}
		if a.SeqNum < 1 || a.Hash == "" {
			return nil, errors.New("anchor requires seq_num and hash")
		}
		return &a, nil
	}
	seq, hash := r.URL.Query().Get("anchor_seq"), r.URL.Query().Get("anchor_hash")
	if seq == "" && hash == "" {
		return nil, nil
	}
	n, err := strconv.ParseInt(seq, 10, 64)
	if err != nil || n < 1 || hash == "" {
		return nil, errors.New("anchor requires anchor_seq and anchor_hash")
	}
	return &Anchor{SeqNum: n, Hash: hash}, nil
}
