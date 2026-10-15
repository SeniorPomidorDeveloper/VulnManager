package deduptest

import (
	"reflect"
	"testing"

	"vulnmanager/services/processing/internal/dedup"
)

const pointsPerUnit = 1000

type Pair struct {
	Name string
	A, B dedup.Record
}

func RunScorerSuite(t *testing.T, scorer dedup.Scorer, pairs []Pair) {
	t.Helper()

	t.Run("declares identity", func(t *testing.T) {
		if scorer.ID() == "" || scorer.Version() < 1 {
			t.Fatalf("incomplete declaration: id=%q version=%d", scorer.ID(), scorer.Version())
		}
	})

	for _, pair := range pairs {
		t.Run(pair.Name, func(t *testing.T) {
			decision := scorer.Score(pair.A, pair.B)

			if decision.Confidence < 0 || decision.Confidence > 1 {
				t.Fatalf("confidence out of range: %v", decision.Confidence)
			}
			if mirrored := scorer.Score(pair.B, pair.A); !reflect.DeepEqual(mirrored, decision) {
				t.Fatalf("not symmetric: %+v vs %+v", decision, mirrored)
			}
			if again := scorer.Score(pair.A, pair.B); !reflect.DeepEqual(again, decision) {
				t.Fatalf("not deterministic: %+v vs %+v", decision, again)
			}
			if restored := restore(decision.Reasons); restored != decision.Confidence {
				t.Fatalf("reasons give %v, confidence is %v", restored, decision.Confidence)
			}
		})
	}
}

func restore(reasons []dedup.MatchReason) float64 {
	var total dedup.Points
	for _, reason := range reasons {
		total += reason.Points
	}
	return float64(min(max(total, 0), pointsPerUnit)) / pointsPerUnit
}
