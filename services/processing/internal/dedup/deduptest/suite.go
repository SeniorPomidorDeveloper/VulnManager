package deduptest

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/dedup"
	"vulnmanager/services/processing/internal/fingerprint"
)

type Fixture interface {
	dedup.Index
	Add(scope model.Scope, finding model.FindingID, keys []dedup.BlockKey)
}

func RunBlockerSuite(t *testing.T, blocker dedup.Blocker, subject dedup.Subject) {
	t.Helper()

	t.Run("declares identity", func(t *testing.T) {
		if blocker.ID() == "" || blocker.Version() < 1 {
			t.Fatalf("incomplete declaration: id=%q version=%d", blocker.ID(), blocker.Version())
		}
	})

	t.Run("no fingerprints give no keys", func(t *testing.T) {
		if keys := blocker.Keys(dedup.Subject{Finding: subject.Finding, Scope: subject.Scope}); len(keys) != 0 {
			t.Fatalf("got %v", keys)
		}
	})

	t.Run("keys do not depend on fingerprint order", func(t *testing.T) {
		want := blocker.Keys(subject)
		reversed := subject
		reversed.Fingerprints = slices.Clone(subject.Fingerprints)
		slices.Reverse(reversed.Fingerprints)
		if got := blocker.Keys(reversed); !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("keys are unique", func(t *testing.T) {
		doubled := subject
		doubled.Fingerprints = append(slices.Clone(subject.Fingerprints), subject.Fingerprints...)
		if got, want := blocker.Keys(doubled), blocker.Keys(subject); !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}

func RunIndexSuite(t *testing.T, newFixture func() Fixture) {
	t.Helper()
	scope := suiteScope(t, "product")
	other := suiteScope(t, "other")
	key := dedup.BlockKey{Level: fingerprint.LevelStructural, Value: "v1:l2:sha256:aa"}
	unknown := dedup.BlockKey{Level: fingerprint.LevelIdentity, Value: "v1:l1:sha256:bb"}

	t.Run("returns findings sharing a key", func(t *testing.T) {
		fixture := newFixture()
		fixture.Add(scope, "f1", []dedup.BlockKey{key})
		fixture.Add(scope, "f2", []dedup.BlockKey{key, unknown})

		hits, err := fixture.Lookup(context.Background(), scope, []dedup.BlockKey{key})
		if err != nil {
			t.Fatal(err)
		}
		if got := hitFindings(hits); !reflect.DeepEqual(got, []model.FindingID{"f1", "f2"}) {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("never crosses scopes", func(t *testing.T) {
		fixture := newFixture()
		fixture.Add(other, "foreign", []dedup.BlockKey{key})

		hits, err := fixture.Lookup(context.Background(), scope, []dedup.BlockKey{key})
		if err != nil || len(hits) != 0 {
			t.Fatalf("hits=%v err=%v", hits, err)
		}
	})

	t.Run("unknown and empty keys give nothing", func(t *testing.T) {
		fixture := newFixture()
		fixture.Add(scope, "f1", []dedup.BlockKey{key})

		for _, keys := range [][]dedup.BlockKey{{unknown}, nil} {
			hits, err := fixture.Lookup(context.Background(), scope, keys)
			if err != nil || len(hits) != 0 {
				t.Fatalf("keys=%v hits=%v err=%v", keys, hits, err)
			}
		}
	})
}

func suiteScope(t *testing.T, product model.ProductID) model.Scope {
	t.Helper()
	scope, err := model.NewScope("tenant", product, "")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func hitFindings(hits []dedup.Hit) []model.FindingID {
	findings := make([]model.FindingID, 0, len(hits))
	for _, hit := range hits {
		findings = append(findings, hit.Finding)
	}
	slices.Sort(findings)
	return slices.Compact(findings)
}
