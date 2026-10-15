package deduptest

import (
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/dedup"
)

const shuffles = 20

func RunClustererSuite(t *testing.T, clusterer dedup.Clusterer, input dedup.Input) {
	t.Helper()
	want := clusterer.Cluster(input)

	t.Run("declares identity", func(t *testing.T) {
		if clusterer.ID() == "" || clusterer.Version() < 1 {
			t.Fatalf("incomplete declaration: id=%q version=%d", clusterer.ID(), clusterer.Version())
		}
	})

	t.Run("places every new finding exactly once", func(t *testing.T) {
		placed := make([]model.FindingID, 0, len(want.Assignments))
		for _, assignment := range want.Assignments {
			placed = append(placed, assignment.Finding)
		}
		expected := slices.Sorted(slices.Values(input.Findings))
		if !slices.Equal(placed, expected) {
			t.Fatalf("placed %v, want %v", placed, expected)
		}
	})

	t.Run("never joins findings the scorer separated", func(t *testing.T) {
		refs := refsOf(input, want)
		for _, edge := range input.Edges {
			left, right := refs[edge.A], refs[edge.B]
			if edge.Decision.Verdict == dedup.VerdictSeparate && left == right && left != (dedup.ClusterRef{}) {
				t.Fatalf("%s and %s share %+v despite separate verdict", edge.A, edge.B, left)
			}
		}
	})

	t.Run("does not depend on input order", func(t *testing.T) {
		rng := rand.New(rand.NewPCG(1, 2))
		for range shuffles {
			shuffled := dedup.Input{
				Findings: slices.Clone(input.Findings),
				Existing: input.Existing,
				Edges:    slices.Clone(input.Edges),
			}
			rng.Shuffle(len(shuffled.Findings), func(i, j int) {
				shuffled.Findings[i], shuffled.Findings[j] = shuffled.Findings[j], shuffled.Findings[i]
			})
			rng.Shuffle(len(shuffled.Edges), func(i, j int) {
				shuffled.Edges[i], shuffled.Edges[j] = shuffled.Edges[j], shuffled.Edges[i]
			})
			if got := clusterer.Cluster(shuffled); !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		}
	})
}

func refsOf(input dedup.Input, result dedup.Result) map[model.FindingID]dedup.ClusterRef {
	refs := map[model.FindingID]dedup.ClusterRef{}
	for finding, cluster := range input.Existing {
		refs[finding] = dedup.ClusterRef{Existing: cluster}
	}
	for _, assignment := range result.Assignments {
		refs[assignment.Finding] = assignment.Cluster
	}
	return refs
}
