// Package metrics defines NHIID's Prometheus instrumentation and a /metrics handler. Metric names
// match docs/RUNBOOK.md so the documented alerts (ingestion lag, job failures) are real.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// HTTP — API request latency/volume by route+status.
	HTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nhiid_http_request_duration_seconds",
		Help:    "API request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route", "status"})

	// Collectors — duration, errors, and records upserted per collector.
	CollectorDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nhiid_collector_run_duration_seconds",
		Help:    "Collector run duration in seconds.",
		Buckets: []float64{.5, 1, 2, 5, 10, 30, 60, 120, 300},
	}, []string{"collector"})
	CollectorErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nhiid_collector_errors_total",
		Help: "Total collector errors.",
	}, []string{"collector"})
	RecordsUpserted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nhiid_records_upserted_total",
		Help: "Total normalized records upserted.",
	}, []string{"collector"})

	// Worker jobs.
	JobsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nhiid_jobs_total",
		Help: "Total worker jobs run.",
	}, []string{"job"})
	JobsFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nhiid_jobs_failed_total",
		Help: "Total worker jobs that failed.",
	}, []string{"job"})

	// Alerting — findings dispatched to notifiers.
	AlertsSent = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nhiid_alerts_sent_total",
		Help: "Total finding alerts dispatched, by severity.",
	}, []string{"severity"})
	AlertsFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nhiid_alerts_failed_total",
		Help: "Total alert dispatch failures (left pending for retry).",
	})

	// Derived gauges (refreshed periodically from the store).
	FindingsOpen = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nhiid_findings_open",
		Help: "Open findings by severity.",
	}, []string{"severity"})
	IngestionLagSeconds = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nhiid_ingestion_lag_seconds",
		Help: "Seconds since the newest ingested usage event, by source.",
	}, []string{"source"})
	IdentitiesTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "nhiid_identities_total",
		Help: "Total identities in inventory.",
	})
)

// Handler serves the Prometheus exposition format.
func Handler() http.Handler { return promhttp.Handler() }
