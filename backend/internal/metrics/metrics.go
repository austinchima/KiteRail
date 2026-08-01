package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HttpRequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kiterail_http_requests_total",
		Help: "The total number of HTTP requests handled by the proxy",
	})
	
	HttpRequestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "kiterail_http_request_duration_seconds",
		Help: "The duration of HTTP requests in seconds",
		Buckets: prometheus.DefBuckets,
	})

	DecisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kiterail_decisions_total",
		Help: "The total number of policy decisions made",
	}, []string{"action"})
)
