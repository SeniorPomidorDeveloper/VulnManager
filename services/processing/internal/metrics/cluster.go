package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"vulnmanager/services/processing/internal/worker"
)

func newClusterMetrics() clusterMetrics {
	return clusterMetrics{
		candidates: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "vulnmanager_processing_candidates_per_finding",
			Help:    "Candidate findings found by blocking for one finding.",
			Buckets: []float64{0, 1, 2, 3, 5, 10, 25, 50, 100, 500, 1000},
		}),
		confidence: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "vulnmanager_processing_cluster_confidence",
			Help:    "Confidence of the decision that placed a finding into its cluster.",
			Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1},
		}),
		verdicts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnmanager_processing_pair_verdicts_total",
			Help: "Scored finding pairs, by tool and verdict.",
		}, []string{"tool", "verdict"}),
		created: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnmanager_processing_clusters_created_total",
			Help: "Clusters created by processing, by tool.",
		}, []string{"tool"}),
		joined: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnmanager_processing_cluster_joins_total",
			Help: "Findings that joined an existing cluster, by tool.",
		}, []string{"tool"}),
		review: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vulnmanager_processing_review_pairs_total",
			Help: "Pairs left in the grey zone or refused by constraints.",
		}),
		unclustered: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vulnmanager_processing_unclustered_candidates_total",
			Help: "Candidates skipped because they have no cluster yet.",
		}),
		algo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vulnmanager_processing_dedup_algo_version_info",
			Help: "Deduplication algorithm versions in use.",
		}, []string{"algo"}),
	}
}

func (c clusterMetrics) register(reg prometheus.Registerer) {
	reg.MustRegister(c.candidates, c.confidence, c.verdicts, c.created, c.joined, c.review, c.unclustered, c.algo)
}

func (c clusterMetrics) record(tool string, stats worker.ClusterStats) {
	for _, count := range stats.Candidates {
		c.candidates.Observe(float64(count))
	}
	for _, confidence := range stats.Confidences {
		c.confidence.Observe(confidence)
	}
	for verdict, count := range stats.Verdicts {
		c.verdicts.WithLabelValues(tool, string(verdict)).Add(float64(count))
	}
	c.created.WithLabelValues(tool).Add(float64(stats.Created))
	c.joined.WithLabelValues(tool).Add(float64(stats.Joined))
	c.review.Add(float64(stats.Review))
	c.unclustered.Add(float64(stats.Unclustered))
	c.algo.WithLabelValues(stats.AlgoVersion).Set(1)
}
