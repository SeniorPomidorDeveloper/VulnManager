package dedup_test

import (
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/dedup"
	"vulnmanager/services/processing/internal/dedup/deduptest"
)

func edge(a, b model.FindingID, verdict dedup.Verdict, confidence float64) dedup.Edge {
	reasons := []dedup.MatchReason{{Feature: dedup.FeatureVuln, Signal: dedup.SignalAgree, Points: dedup.Points(confidence * 1000)}}
	return dedup.Edge{A: a, B: b, Decision: dedup.Decision{Confidence: confidence, Verdict: verdict, Reasons: reasons}}
}

func merge(a, b model.FindingID, confidence float64) dedup.Edge {
	return edge(a, b, dedup.VerdictMerge, confidence)
}

func cluster(t *testing.T, input dedup.Input) dedup.Result {
	t.Helper()
	deduptest.RunClustererSuite(t, dedup.Constrained{}, input)
	return dedup.Constrained{}.Cluster(input)
}

func refs(result dedup.Result) map[model.FindingID]dedup.ClusterRef {
	refs := map[model.FindingID]dedup.ClusterRef{}
	for _, assignment := range result.Assignments {
		refs[assignment.Finding] = assignment.Cluster
	}
	return refs
}

func TestClusterChainsMergesIntoOneCluster(t *testing.T) {
	got := refs(cluster(t, dedup.Input{
		Findings: []model.FindingID{"c", "a", "b", "d"},
		Edges:    []dedup.Edge{merge("a", "b", 0.9), merge("c", "b", 0.85)},
	}))

	seed := dedup.ClusterRef{Seed: "a"}
	if got["a"] != seed || got["b"] != seed || got["c"] != seed {
		t.Fatalf("got %+v", got)
	}
	if got["d"] != (dedup.ClusterRef{Seed: "d"}) {
		t.Fatalf("d must be alone: %+v", got["d"])
	}
}

func TestClusterRespectsCannotLinkAcrossTransitiveMerge(t *testing.T) {
	result := cluster(t, dedup.Input{
		Findings: []model.FindingID{"a", "b", "c"},
		Edges: []dedup.Edge{
			merge("a", "b", 0.95), merge("b", "c", 0.85), edge("a", "c", dedup.VerdictSeparate, 0),
		},
	})

	got := refs(result)
	if got["a"] != got["b"] || got["c"] == got["a"] {
		t.Fatalf("c must stay out of {a, b}: %+v", got)
	}
	if len(result.Review) != 1 || result.Review[0].A != "b" || result.Review[0].B != "c" {
		t.Fatalf("refused link must be reviewed: %+v", result.Review)
	}
}

func TestClusterKeepsGreyZoneApart(t *testing.T) {
	result := cluster(t, dedup.Input{
		Findings: []model.FindingID{"a", "b"},
		Edges:    []dedup.Edge{edge("a", "b", dedup.VerdictReview, 0.6)},
	})

	got := refs(result)
	if got["a"] == got["b"] || len(result.Review) != 1 {
		t.Fatalf("grey zone must not merge: %+v, review %+v", got, result.Review)
	}
}

func TestClusterJoinsExistingClusterAndKeepsItIntact(t *testing.T) {
	result := cluster(t, dedup.Input{
		Findings: []model.FindingID{"n"},
		Existing: map[model.FindingID]dedup.ClusterID{"e1": "C1", "e2": "C1"},
		Edges:    []dedup.Edge{merge("n", "e1", 0.9)},
	})

	if got := result.Assignments[0]; got.Cluster != (dedup.ClusterRef{Existing: "C1"}) || got.Confidence != 0.9 || len(got.Reasons) != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestClusterNeverMergesTwoExistingClusters(t *testing.T) {
	result := cluster(t, dedup.Input{
		Findings: []model.FindingID{"n"},
		Existing: map[model.FindingID]dedup.ClusterID{"e1": "C1", "e2": "C2"},
		Edges:    []dedup.Edge{merge("n", "e1", 0.9), merge("n", "e2", 0.85)},
	})

	if got := result.Assignments[0].Cluster; got != (dedup.ClusterRef{Existing: "C1"}) {
		t.Fatalf("must join the strongest cluster: %+v", got)
	}
	if len(result.Review) != 1 || result.Review[0].B != "n" && result.Review[0].A != "n" {
		t.Fatalf("second link must be reviewed: %+v", result.Review)
	}
}

func TestClusterRespectsCannotLinkAgainstExisting(t *testing.T) {
	result := cluster(t, dedup.Input{
		Findings: []model.FindingID{"n", "m"},
		Existing: map[model.FindingID]dedup.ClusterID{"e1": "C1"},
		Edges:    []dedup.Edge{merge("n", "m", 0.9), merge("m", "e1", 0.8), edge("n", "e1", dedup.VerdictSeparate, 0)},
	})

	got := refs(result)
	if got["n"] != got["m"] || got["n"] == (dedup.ClusterRef{Existing: "C1"}) {
		t.Fatalf("n and m must stay together outside C1: %+v", got)
	}
	if len(result.Review) != 1 || result.Review[0].A != "e1" && result.Review[0].B != "e1" {
		t.Fatalf("refused link to C1 must be reviewed: %+v", result.Review)
	}
}

func TestClusterLoneFindingGetsOwnClusterWithFullConfidence(t *testing.T) {
	result := cluster(t, dedup.Input{Findings: []model.FindingID{"x"}})

	if got := result.Assignments[0]; got.Cluster != (dedup.ClusterRef{Seed: "x"}) || got.Confidence != 1 || len(got.Reasons) != 0 {
		t.Fatalf("got %+v", got)
	}
}
