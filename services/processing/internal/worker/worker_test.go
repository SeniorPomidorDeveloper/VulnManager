package worker_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/fingerprint"
	"vulnmanager/services/processing/internal/store"
	"vulnmanager/services/processing/internal/worker"
)

var errBoom = errors.New("boom")

type fakeTx struct {
	run       store.Run
	runErr    error
	processed bool
	findings  []model.Finding
	added     []store.Item
	algo      string
}

type fakeStore struct {
	tx *fakeTx
}

func (s fakeStore) InTx(_ context.Context, fn func(store.Tx) error) error {
	return fn(s.tx)
}

func (t *fakeTx) Run(context.Context, model.TenantID, model.ImportRunID) (store.Run, error) {
	return t.run, t.runErr
}

func (t *fakeTx) Begin(_ context.Context, _ store.Run, algo string) (bool, error) {
	t.algo = algo
	return !t.processed, nil
}

func (t *fakeTx) Findings(context.Context, store.Run) ([]model.Finding, error) {
	return t.findings, nil
}

func (t *fakeTx) AddFingerprints(_ context.Context, _ store.Run, items []store.Item) error {
	t.added = append(t.added, items...)
	return nil
}

func newWorker(t *testing.T, tx *fakeTx) *worker.Worker {
	t.Helper()
	full, err := fingerprint.NewSet(fingerprint.ToolUID{}, fingerprint.Structural{})
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := fingerprint.NewSet(fingerprint.ToolUID{})
	if err != nil {
		t.Fatal(err)
	}
	registry := fingerprint.NewRegistry(fallback)
	if err := registry.Register("semgrep", full); err != nil {
		t.Fatal(err)
	}
	w, err := worker.New(fakeStore{tx: tx}, registry)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func testRun(t *testing.T, tool model.ToolName) store.Run {
	t.Helper()
	scope, err := model.NewScope("tenant", "product", "")
	if err != nil {
		t.Fatal(err)
	}
	return store.Run{ID: "run", Scope: scope, Tool: tool}
}

func finding(run store.Run, id, toolID string, location string) model.Finding {
	return model.Finding{
		ID: model.FindingID(id), Scope: run.Scope, ToolFindingID: model.ToolFindingID(toolID),
		RuleID: "rule", Provenance: model.Provenance{Tool: run.Tool}, Location: json.RawMessage(location),
	}
}

func TestHandleStoresFingerprintsAndCountsSkips(t *testing.T) {
	run := testRun(t, "semgrep")
	tx := &fakeTx{run: run, findings: []model.Finding{
		finding(run, "f1", "a", `{"uri":"a.go","snippet":"x"}`),
		finding(run, "f2", "b", `{"uri":"b.go"}`),
		{ID: "f3", Scope: run.Scope},
	}}

	got, err := newWorker(t, tx).Handle(context.Background(), "tenant", "run")
	if err != nil {
		t.Fatal(err)
	}

	if len(tx.added) != 3 || tx.algo != "tool-uid@1+structural@1" {
		t.Fatalf("added=%d algo=%q", len(tx.added), tx.algo)
	}
	if got.Findings != 3 || got.Unfingerprinted != 1 || got.Already || got.Tool != "semgrep" {
		t.Fatalf("result: %+v", got)
	}
	if got.Skipped[fingerprint.LevelStructural] != 2 || got.Skipped[fingerprint.LevelToolUID] != 1 {
		t.Fatalf("skipped: %+v", got.Skipped)
	}
}

func TestHandleUsesFallbackForUnknownTool(t *testing.T) {
	run := testRun(t, "other")
	tx := &fakeTx{run: run, findings: []model.Finding{finding(run, "f1", "a", "")}}

	if _, err := newWorker(t, tx).Handle(context.Background(), "tenant", "run"); err != nil {
		t.Fatal(err)
	}
	if tx.algo != "tool-uid@1" || len(tx.added) != 1 {
		t.Fatalf("algo=%q added=%d", tx.algo, len(tx.added))
	}
}

func TestHandleSkipsProcessedRun(t *testing.T) {
	run := testRun(t, "semgrep")
	tx := &fakeTx{run: run, processed: true, findings: []model.Finding{finding(run, "f1", "a", "")}}

	got, err := newWorker(t, tx).Handle(context.Background(), "tenant", "run")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Already || len(tx.added) != 0 {
		t.Fatalf("result=%+v added=%d", got, len(tx.added))
	}
}

func TestHandlePropagatesRunError(t *testing.T) {
	tx := &fakeTx{runErr: errBoom}
	if _, err := newWorker(t, tx).Handle(context.Background(), "tenant", "run"); !errors.Is(err, errBoom) {
		t.Fatalf("got %v", err)
	}
}

func TestNewRejectsMissingDeps(t *testing.T) {
	if _, err := worker.New(nil, nil); !errors.Is(err, worker.ErrInvalidConfig) {
		t.Fatalf("got %v", err)
	}
}
