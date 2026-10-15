package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/worker"
)

const (
	resultProcessed = "processed"
	resultAlready   = "already"
	resultFailed    = "failed"
	toolOther       = "other"
)

type clusterMetrics struct {
	candidates  prometheus.Histogram
	confidence  prometheus.Histogram
	verdicts    *prometheus.CounterVec
	created     *prometheus.CounterVec
	joined      *prometheus.CounterVec
	review      prometheus.Counter
	unclustered prometheus.Counter
	algo        *prometheus.GaugeVec
}

type Metrics struct {
	known           func(model.ToolName) bool
	runs            *prometheus.CounterVec
	duration        prometheus.Histogram
	findings        *prometheus.CounterVec
	unfingerprinted *prometheus.CounterVec
	skipped         *prometheus.CounterVec
	algo            *prometheus.GaugeVec
	cluster         clusterMetrics
}

func New(reg prometheus.Registerer, known func(model.ToolName) bool) *Metrics {
	m := &Metrics{
		known: known,
		runs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnmanager_processing_runs_total",
			Help: "Import runs handled by processing, by result.",
		}, []string{"result"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "vulnmanager_processing_run_duration_seconds",
			Help:    "Time to fingerprint one import run.",
			Buckets: prometheus.DefBuckets,
		}),
		findings: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnmanager_processing_findings_total",
			Help: "Findings fingerprinted by processing, by tool.",
		}, []string{"tool"}),
		unfingerprinted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnmanager_processing_unfingerprinted_findings_total",
			Help: "Findings with no computable fingerprint, by tool.",
		}, []string{"tool"}),
		skipped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnmanager_processing_skipped_levels_total",
			Help: "Fingerprint levels that could not be computed, by tool and level.",
		}, []string{"tool", "level"}),
		algo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vulnmanager_processing_algo_version_info",
			Help: "Fingerprint algorithm version used for the tool.",
		}, []string{"tool", "algo"}),
	}
	m.cluster = newClusterMetrics()
	reg.MustRegister(m.runs, m.duration, m.findings, m.unfingerprinted, m.skipped, m.algo)
	m.cluster.register(reg)
	return m
}

func (m *Metrics) Record(result worker.Result, took time.Duration, err error) {
	m.duration.Observe(took.Seconds())
	if err != nil {
		m.runs.WithLabelValues(resultFailed).Inc()
		return
	}
	if result.Already {
		m.runs.WithLabelValues(resultAlready).Inc()
		return
	}
	tool := m.label(result.Tool)
	m.runs.WithLabelValues(resultProcessed).Inc()
	m.findings.WithLabelValues(tool).Add(float64(result.Findings))
	m.unfingerprinted.WithLabelValues(tool).Add(float64(result.Unfingerprinted))
	for level, count := range result.Skipped {
		m.skipped.WithLabelValues(tool, string(level)).Add(float64(count))
	}
	m.algo.WithLabelValues(tool, result.AlgoVersion).Set(1)
	m.cluster.record(tool, result.Cluster)
}

func (m *Metrics) label(tool model.ToolName) string {
	if m.known(tool) {
		return string(tool)
	}
	return toolOther
}
