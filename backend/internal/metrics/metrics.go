package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "elodea_http_requests_total",
		Help: "The total number of HTTP requests handled by the proxy",
	})

	HTTPRequestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "elodea_http_request_duration_seconds",
		Help:    "The duration of HTTP requests in seconds",
		Buckets: prometheus.DefBuckets,
	})

	DecisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "elodea_decisions_total",
		Help: "The total number of policy decisions made",
	}, []string{"action"})

	LedgerAppendDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "elodea_ledger_append_duration_seconds",
		Help:    "Time to append one entry to the hash-chained audit ledger",
		Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
	})

	LedgerAppendFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "elodea_ledger_append_failures_total",
		Help: "Ledger appends that failed after retries (requests fail closed)",
	})

	ReplayOutcomesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "elodea_replay_outcomes_total",
		Help: "Outcomes of approved quarantine replays",
	}, []string{"outcome"})

	NotificationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "elodea_notifications_total",
		Help: "Held-action notification attempts by channel and outcome (delivered, skipped, retrying, gave_up)",
	}, []string{"channel", "outcome"})

	PolicyReloadsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "elodea_policy_reloads_total",
		Help: "Policy bundle reload attempts by result",
	}, []string{"result"})

	PolicyInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "elodea_policy_info",
		Help: "Always 1; the policy_version label identifies the active policy bundle",
	}, []string{"policy_version"})

	BuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "elodea_build_info",
		Help: "Always 1; labels identify the running build",
	}, []string{"version"})
)

// SetPolicyVersion publishes the active policy bundle version.
func SetPolicyVersion(version string) {
	PolicyInfo.Reset()
	PolicyInfo.WithLabelValues(version).Set(1)
}
