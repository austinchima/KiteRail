package policystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/austinchima/kiterail/internal/mcp"
	"github.com/austinchima/kiterail/internal/opaengine"
	"github.com/austinchima/kiterail/internal/types"
	"go.uber.org/zap"
)

// maxSimulationBodyBytes prevents an authenticated simulator request from
// bypassing the ingress body's one-megabyte resource limit.
const maxSimulationBodyBytes int64 = 1 << 20

// Handler represents the HTTP handler for policies.
type Handler struct {
	store  *Store
	engine *opaengine.Engine
	logger *zap.Logger
}

// NewHandler creates a new policy handler.
func NewHandler(store *Store, engine *opaengine.Engine, logger *zap.Logger) *Handler {
	return &Handler{
		store:  store,
		engine: engine,
		logger: logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/simulate") {
		h.handleSimulate(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleList(w, r)
	case http.MethodPatch, http.MethodPut, http.MethodPost:
		// Policies are immutable GitOps assets in v1.0: change them via git,
		// not the API. Runtime policy mutation would let a single compromised
		// admin credential rewrite the enforcement rulebook.
		http.Error(w, `{"error": "policies are immutable; modify via version control"}`, http.StatusMethodNotAllowed)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	policies, err := h.store.List(r.Context())
	if err != nil {
		h.logger.Error("Failed to list policies", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

func (h *Handler) handleSimulate(w http.ResponseWriter, r *http.Request) {
	var input types.EvalInput
	r.Body = http.MaxBytesReader(w, r.Body, maxSimulationBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "Request body exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	object, err := mcp.DecodeObject(body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// Re-marshal the validated object so the standard decoder can populate the
	// typed input. json.Number preserves client numeric values through this
	// conversion; DecodeObject already rejected duplicate keys and batches.
	normalized, err := json.Marshal(object)
	if err != nil {
		h.logger.Error("failed to normalize simulation input", zap.Error(err))
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	decoder.UseNumber()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if input.Tool == "" || input.Agent == "" {
		http.Error(w, "tool and agent are required", http.StatusBadRequest)
		return
	}

	// Default values for simulation if omitted. RawMethod is deliberately NOT
	// defaulted: simulation must run the identical input the proxy would send.
	// RawMethod is the JSON-RPC protocol method from the validated body (see
	// types.EvalInput); send "tools/call" here to replicate a runtime
	// tools/call evaluation.
	if input.Timestamp.IsZero() {
		input.Timestamp = time.Now()
	}

	start := time.Now()
	decision, err := h.engine.Evaluate(r.Context(), input)
	decision.LatencyMs = time.Since(start).Seconds() * 1000

	if err != nil {
		h.logger.Error("Simulation failed", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(decision)
}
