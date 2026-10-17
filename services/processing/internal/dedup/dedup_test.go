package dedup_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/dedup"
	"vulnmanager/services/processing/internal/dedup/deduptest"
	"vulnmanager/services/processing/internal/fingerprint"
)

const (
	linearFindings = 100_000
	linearBudget   = time.Minute
	blockSize      = 4
)

func scope(t *testing.T, product model.ProductID) model.Scope {
	t.Helper()
	result, err := model.NewScope("tenant", product, "")
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func subject(t *testing.T, finding model.FindingID, values ...fingerprint.Value) dedup.Subject {
	t.Helper()
	fingerprints := make([]fingerprint.Fingerprint, 0, len(values))
	levels := []fingerprint.Level{fingerprint.LevelToolUID, fingerprint.LevelIdentity, fingerprint.LevelStructural}
	for i, value := range values {
		fingerprints = append(fingerprints, fingerprint.Fingerprint{Level: levels[i], Value: value})
	}
	return dedup.Subject{Finding: finding, Scope: scope(t, "product"), Fingerprints: fingerprints}
}

func TestBlockerContract(t *testing.T) {
	deduptest.RunBlockerSuite(t, dedup.ByLevel{}, subject(t, "f1", "a", "b"))
}

func TestMemoryIndexContract(t *testing.T) {
	deduptest.RunIndexSuite(t, func() deduptest.Fixture { return deduptest.NewMemoryIndex() })
}

func TestFindGroupsHitsPerCandidateAndSkipsSelf(t *testing.T) {
	index := deduptest.NewMemoryIndex()
	blocker := dedup.ByLevel{}
	for _, other := range []dedup.Subject{subject(t, "f1", "a", "b"), subject(t, "f2", "x", "b"), subject(t, "f3", "q", "z")} {
		index.Add(other.Scope, other.Finding, blocker.Keys(other))
	}
	incoming := subject(t, "f1", "a", "b")

	got, err := dedup.Find(context.Background(), blocker, index, incoming)
	if err != nil {
		t.Fatal(err)
	}

	want := []dedup.Candidate{{Finding: "f2", Keys: []dedup.BlockKey{{Level: fingerprint.LevelIdentity, Value: "b"}}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestFindWithoutFingerprintsReturnsNothing(t *testing.T) {
	got, err := dedup.Find(context.Background(), dedup.ByLevel{}, deduptest.NewMemoryIndex(), subject(t, "f1"))
	if err != nil || got != nil {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestFindRequiresTenant(t *testing.T) {
	incoming := subject(t, "f1", "a")
	incoming.Scope = model.Scope{}

	_, err := dedup.Find(context.Background(), dedup.ByLevel{}, deduptest.NewMemoryIndex(), incoming)
	if !errors.Is(err, model.ErrEmptyTenant) {
		t.Fatalf("got %v", err)
	}
}

func TestFindIsIndependentOfInsertionOrder(t *testing.T) {
	blocker := dedup.ByLevel{}
	forward, backward := deduptest.NewMemoryIndex(), deduptest.NewMemoryIndex()
	findings := []dedup.Subject{subject(t, "f2", "a"), subject(t, "f3", "a"), subject(t, "f4", "a")}
	for _, item := range findings {
		forward.Add(item.Scope, item.Finding, blocker.Keys(item))
	}
	for i := len(findings) - 1; i >= 0; i-- {
		backward.Add(findings[i].Scope, findings[i].Finding, blocker.Keys(findings[i]))
	}
	incoming := subject(t, "f1", "a")

	first, _ := dedup.Find(context.Background(), blocker, forward, incoming)
	second, _ := dedup.Find(context.Background(), blocker, backward, incoming)

	if !reflect.DeepEqual(first, second) || len(first) != 3 {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
}

func TestBlockingStaysLinearOnLargeScope(t *testing.T) {
	if testing.Short() {
		t.Skip("large scope")
	}
	blocker := dedup.ByLevel{}
	index := deduptest.NewMemoryIndex()
	subjects := make([]dedup.Subject, 0, linearFindings)
	for i := range linearFindings {
		item := subject(t, model.FindingID(fmt.Sprintf("f%d", i)),
			fingerprint.Value(fmt.Sprintf("uid-%d", i)), fingerprint.Value(fmt.Sprintf("identity-%d", i/blockSize)))
		subjects = append(subjects, item)
		index.Add(item.Scope, item.Finding, blocker.Keys(item))
	}

	started := time.Now()
	candidates := 0
	for _, item := range subjects {
		found, err := dedup.Find(context.Background(), blocker, index, item)
		if err != nil {
			t.Fatal(err)
		}
		candidates += len(found)
	}

	if want := linearFindings * (blockSize - 1); candidates != want {
		t.Fatalf("candidates=%d, want %d", candidates, want)
	}
	if took := time.Since(started); took > linearBudget {
		t.Fatalf("took %s, budget %s", took, linearBudget)
	}
}

func TestFindManyMatchesFindForEverySubject(t *testing.T) {
	blocker := dedup.ByLevel{}
	index := deduptest.NewMemoryIndex()
	subjects := []dedup.Subject{
		subject(t, "f1", "a", "b"), subject(t, "f2", "x", "b"), subject(t, "f3", "a", "z"), subject(t, "f4", "q", "r"),
	}
	for _, item := range subjects {
		index.Add(item.Scope, item.Finding, blocker.Keys(item))
	}

	many, err := dedup.FindMany(context.Background(), blocker, index, scope(t, "product"), subjects)
	if err != nil {
		t.Fatal(err)
	}

	for _, item := range subjects {
		one, err := dedup.Find(context.Background(), blocker, index, item)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(many[item.Finding], one) {
			t.Fatalf("%s: many=%+v one=%+v", item.Finding, many[item.Finding], one)
		}
	}
}

func TestFindManyRequiresTenant(t *testing.T) {
	_, err := dedup.FindMany(context.Background(), dedup.ByLevel{}, deduptest.NewMemoryIndex(), model.Scope{}, nil)
	if !errors.Is(err, model.ErrEmptyTenant) {
		t.Fatalf("got %v", err)
	}
}
