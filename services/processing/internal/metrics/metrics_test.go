package metrics

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/dedup"
	"vulnmanager/services/processing/internal/fingerprint"
	"vulnmanager/services/processing/internal/worker"
)

func newMetrics() *Metrics {
	return New(prometheus.NewRegistry(), func(tool model.ToolName) bool { return tool == "trivy" })
}

func TestRecordProcessedRun(t *testing.T) {
	m := newMetrics()

	m.Record(worker.Result{
		Tool: "trivy", AlgoVersion: "tool-uid@1", Findings: 5, Unfingerprinted: 1,
		Skipped: map[fingerprint.Level]int{fingerprint.LevelIdentity: 2},
	}, time.Second, nil)

	checks := map[string]float64{
		"runs":            testutil.ToFloat64(m.runs.WithLabelValues("processed")),
		"findings":        testutil.ToFloat64(m.findings.WithLabelValues("trivy")),
		"unfingerprinted": testutil.ToFloat64(m.unfingerprinted.WithLabelValues("trivy")),
		"skipped":         testutil.ToFloat64(m.skipped.WithLabelValues("trivy", "l1")),
		"algo":            testutil.ToFloat64(m.algo.WithLabelValues("trivy", "tool-uid@1")),
	}
	want := map[string]float64{"runs": 1, "findings": 5, "unfingerprinted": 1, "skipped": 2, "algo": 1}
	for name, got := range checks {
		if got != want[name] {
			t.Fatalf("%s: got %v, want %v", name, got, want[name])
		}
	}
}

func TestRecordCollapsesUnknownToolLabel(t *testing.T) {
	m := newMetrics()

	m.Record(worker.Result{Tool: "made-up-tool", Findings: 2, Skipped: map[fingerprint.Level]int{}}, 0, nil)

	if got := testutil.ToFloat64(m.findings.WithLabelValues("other")); got != 2 {
		t.Fatalf("got %v, want 2", got)
	}
}

func TestRecordAlreadyProcessedAndFailedRuns(t *testing.T) {
	m := newMetrics()

	m.Record(worker.Result{Already: true, Tool: "trivy"}, 0, nil)
	m.Record(worker.Result{}, 0, errors.New("boom"))

	if testutil.ToFloat64(m.runs.WithLabelValues("already")) != 1 || testutil.ToFloat64(m.runs.WithLabelValues("failed")) != 1 {
		t.Fatal("already and failed runs must be counted separately")
	}
	if testutil.ToFloat64(m.findings.WithLabelValues("trivy")) != 0 {
		t.Fatal("already processed run must not add findings")
	}
}

func TestRecordClusterStats(t *testing.T) {
	m := newMetrics()

	m.Record(worker.Result{
		Tool: "trivy", AlgoVersion: "tool-uid@1", Skipped: map[fingerprint.Level]int{},
		Cluster: worker.ClusterStats{
			AlgoVersion: "by-level@1+by-kind@1+constrained-union@1",
			Candidates:  []int{0, 3, 3},
			Confidences: []float64{1, 0.85, 0.85},
			Verdicts:    map[dedup.Verdict]int{dedup.VerdictMerge: 2, dedup.VerdictReview: 1},
			Created:     1, Joined: 2, Review: 1, Unclustered: 4,
		},
	}, 0, nil)

	checks := map[string]float64{
		"merge":       testutil.ToFloat64(m.cluster.verdicts.WithLabelValues("trivy", "merge")),
		"review pair": testutil.ToFloat64(m.cluster.verdicts.WithLabelValues("trivy", "review")),
		"created":     testutil.ToFloat64(m.cluster.created.WithLabelValues("trivy")),
		"joined":      testutil.ToFloat64(m.cluster.joined.WithLabelValues("trivy")),
		"grey":        testutil.ToFloat64(m.cluster.review),
		"unclustered": testutil.ToFloat64(m.cluster.unclustered),
		"algo":        testutil.ToFloat64(m.cluster.algo.WithLabelValues("by-level@1+by-kind@1+constrained-union@1")),
	}
	want := map[string]float64{"merge": 2, "review pair": 1, "created": 1, "joined": 2, "grey": 1, "unclustered": 4, "algo": 1}
	for name, got := range checks {
		if got != want[name] {
			t.Fatalf("%s: got %v, want %v", name, got, want[name])
		}
	}
	if count := testutil.CollectAndCount(m.cluster.candidates); count != 1 {
		t.Fatalf("candidate histogram series: %d", count)
	}
}

func TestRecordSkipsClusterStatsForAlreadyProcessedRun(t *testing.T) {
	m := newMetrics()

	m.Record(worker.Result{Already: true, Tool: "trivy", Cluster: worker.ClusterStats{Created: 5}}, 0, nil)

	if got := testutil.ToFloat64(m.cluster.created.WithLabelValues("trivy")); got != 0 {
		t.Fatalf("got %v", got)
	}
}
