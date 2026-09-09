package dashboard

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/ledger"
	"github.com/austinchima/kiterail/internal/quarantine"
)

// Handler represents the HTTP handler for the dashboard.
type Handler struct {
	ledgerStore     *ledger.Store
	quarantineStore *quarantine.Store
	logger          *zap.Logger
}

// statsResponse is the typed API boundary for GET /api/v1/dashboard/stats.
// A struct (not map[string]interface{}) means the wire shape is declared in
// one place and refactors rename fields compile-safely.
type statsResponse struct {
	TotalActionsToday int64                `json:"total_actions_today"`
	PolicyViolations  int64                `json:"policy_violations"`
	PendingApprovals  []db.QuarantineEntry `json:"pending_approvals"`
	ComplianceStatus  float64              `json:"compliance_status"`
	RecentFeed        []db.LedgerEntry     `json:"recent_feed"`
}

// NewHandler creates a new dashboard handler.
func NewHandler(lStore *ledger.Store, qStore *quarantine.Store, logger *zap.Logger) *Handler {
	return &Handler{
		ledgerStore:     lStore,
		quarantineStore: qStore,
		logger:          logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// 1. Get Ledger Stats
	stats, err := h.ledgerStore.Stats(ctx)
	if err != nil {
		h.logger.Error("Failed to get ledger stats", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 2. Get Pending Approvals
	pending, err := h.quarantineStore.List(ctx, "pending")
	if err != nil {
		h.logger.Error("Failed to list pending approvals", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 3. Get Recent Feed
	recent, err := h.ledgerStore.Query(ctx)
	if err != nil {
		h.logger.Error("Failed to query ledger", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Limit feed to last 10 for dashboard
	feed := recent
	if len(feed) > 10 {
		feed = feed[:10]
	}

	resp := statsResponse{
		TotalActionsToday: stats.TotalActionsToday,
		PolicyViolations:  stats.PolicyViolations,
		PendingApprovals:  pending,
		ComplianceStatus:  complianceStatus(stats),
		RecentFeed:        feed,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// complianceStatus returns the percentage of today's actions that were not
// policy violations. With no actions there is no violation evidence, so the
// dashboard reports 100 rather than dividing by zero or implying a failure.
func complianceStatus(stats db.LedgerStats) float64 {
	if stats.TotalActionsToday == 0 {
		return 100
	}
	return (1 - float64(stats.PolicyViolations)/float64(stats.TotalActionsToday)) * 100
}
