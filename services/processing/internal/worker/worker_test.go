package worker_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/adapters"
	"vulnmanager/services/processing/internal/dedup"
	"vulnmanager/services/processing/internal/fingerprint"
	"vulnmanager/services/processing/internal/store"
	"vulnmanager/services/processing/internal/worker"
)

var errBoom = errors.New("boom")

type indexKey struct {
	scope model.ScopeKey
	key   dedup.BlockKey
}

type memory struct {
	runs      map[model.ImportRunID]store.Run
	inRun     map[model.ImportRunID][]model.Finding
	byID      map[model.FindingID]model.Finding
	processed map[model.ImportRunID]bool
	index     map[indexKey][]model.FindingID
	clusterOf map[model.FindingID]dedup.ClusterID
	members   []store.Member
	added     []store.Item
	clusters  int
	locks     int
	algo      string
	runErr    error
}

func newMemory() *memory {
	return &memory{
		runs:      map[model.ImportRunID]store.Run{},
		inRun:     map[model.ImportRunID][]model.Finding{},
		byID:      map[model.FindingID]model.Finding{},
		processed: map[model.ImportRunID]bool{},
		index:     map[indexKey][]model.FindingID{},
		clusterOf: map[model.FindingID]dedup.ClusterID{},
	}
}

func (m *memory) InTx(_ context.Context, fn func(store.Tx) error) error {
	return fn(m)
}

func (m *memory) Run(_ context.Context, _ model.TenantID, id model.ImportRunID) (store.Run, error) {
	return m.runs[id], m.runErr
}

func (m *memory) Begin(_ context.Context, run store.Run, algo string) (bool, error) {
	m.algo = algo
	fresh := !m.processed[run.ID]
	m.processed[run.ID] = true
	return fresh, nil
}

func (m *memory) Findings(_ context.Context, run store.Run) ([]model.Finding, error) {
	return m.inRun[run.ID], nil
}

func (m *memory) AddFingerprints(_ context.Context, run store.Run, items []store.Item) error {
	m.added = append(m.added, items...)
	for _, item := range items {
		slot := indexKey{scope: run.Scope.Key(), key: dedup.BlockKey{Level: item.Fingerprint.Level, Value: item.Fingerprint.Value}}
		m.index[slot] = append(m.index[slot], item.Finding)
	}
	return nil
}

func (m *memory) LockScope(context.Context, model.Scope) error {
	m.locks++
	return nil
}

func (m *memory) Lookup(_ context.Context, scope model.Scope, keys []dedup.BlockKey) ([]dedup.Hit, error) {
	var hits []dedup.Hit
	for _, key := range keys {
		for _, finding := range m.index[indexKey{scope: scope.Key(), key: key}] {
			hits = append(hits, dedup.Hit{Finding: finding, Key: key})
		}
	}
	return hits, nil
}

func (m *memory) FindingsByID(_ context.Context, _ model.Scope, ids []model.FindingID) ([]model.Finding, error) {
	var found []model.Finding
	for _, id := range ids {
		found = append(found, m.byID[id])
	}
	return found, nil
}

func (m *memory) ClustersOf(_ context.Context, _ model.Scope, ids []model.FindingID) (map[model.FindingID]dedup.ClusterID, error) {
	result := map[model.FindingID]dedup.ClusterID{}
	for _, id := range ids {
		if cluster, ok := m.clusterOf[id]; ok {
			result[id] = cluster
		}
	}
	return result, nil
}

func (m *memory) CreateCluster(context.Context, model.Scope, string) (dedup.ClusterID, error) {
	m.clusters++
	return dedup.ClusterID(fmt.Sprintf("C%d", m.clusters)), nil
}

func (m *memory) AddMembers(_ context.Context, _ model.Scope, _ string, members []store.Member) error {
	m.members = append(m.members, members...)
	for _, member := range members {
		m.clusterOf[member.Finding] = member.Cluster
	}
	return nil
}

func (m *memory) addRun(run store.Run, findings ...model.Finding) {
	m.runs[run.ID] = run
	m.inRun[run.ID] = findings
	for _, finding := range findings {
		m.byID[finding.ID] = finding
	}
}

func newWorker(t *testing.T, m *memory) *worker.Worker {
	t.Helper()
	full, err := fingerprint.NewSet(fingerprint.ToolUID{}, fingerprint.Structural{})
	if err != nil {
		t.Fatal(err)
	}
	trivy, err := fingerprint.NewSet(fingerprint.ToolUID{}, fingerprint.Identity{})
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := fingerprint.NewSet(fingerprint.ToolUID{})
	if err != nil {
		t.Fatal(err)
	}
	registry := fingerprint.NewRegistry(fallback)
	for tool, set := range map[model.ToolName]fingerprint.Set{"semgrep": full, "trivy": trivy} {
		if err := registry.Register(tool, set); err != nil {
			t.Fatal(err)
		}
	}
	stages, err := adapters.Dedup()
	if err != nil {
		t.Fatal(err)
	}
	w, err := worker.New(m, registry, stages)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func testRun(t *testing.T, id model.ImportRunID, tool model.ToolName) store.Run {
	t.Helper()
	scope, err := model.NewScope("tenant", "product", "")
	if err != nil {
		t.Fatal(err)
	}
	return store.Run{ID: id, Scope: scope, Tool: tool}
}

func finding(run store.Run, id, toolID, location string) model.Finding {
	return model.Finding{
		ID: model.FindingID(id), Scope: run.Scope, ToolFindingID: model.ToolFindingID(toolID),
		RuleID: "rule", Provenance: model.Provenance{Tool: run.Tool}, Location: json.RawMessage(location),
	}
}

func dependency(run store.Run, id, toolID, vuln, purl string) model.Finding {
	item := finding(run, id, toolID, `{"target":"go.mod"}`)
	item.Kind = model.KindSCA
	item.VulnID = model.VulnID{Source: "cve", Value: vuln}
	item.Component = model.Component{PURL: model.PURL(purl)}
	return item
}

func handle(t *testing.T, w *worker.Worker, id model.ImportRunID) worker.Result {
	t.Helper()
	got, err := w.Handle(context.Background(), "tenant", id)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestHandleStoresFingerprintsAndCountsSkips(t *testing.T) {
	m := newMemory()
	run := testRun(t, "run", "semgrep")
	m.addRun(run,
		finding(run, "f1", "a", `{"uri":"a.go","snippet":"x"}`),
		finding(run, "f2", "b", `{"uri":"b.go"}`),
		model.Finding{ID: "f3", Scope: run.Scope},
	)

	got := handle(t, newWorker(t, m), "run")

	if len(m.added) != 3 || m.algo != "tool-uid@1+structural@1" || m.locks != 1 {
		t.Fatalf("added=%d algo=%q locks=%d", len(m.added), m.algo, m.locks)
	}
	if got.Findings != 3 || got.Unfingerprinted != 1 || got.Already || got.Tool != "semgrep" {
		t.Fatalf("result: %+v", got)
	}
	if got.Skipped[fingerprint.LevelStructural] != 2 || got.Skipped[fingerprint.LevelToolUID] != 1 {
		t.Fatalf("skipped: %+v", got.Skipped)
	}
}

func TestHandleUsesFallbackForUnknownTool(t *testing.T) {
	m := newMemory()
	run := testRun(t, "run", "other")
	m.addRun(run, finding(run, "f1", "a", ""))

	handle(t, newWorker(t, m), "run")

	if m.algo != "tool-uid@1" || len(m.added) != 1 {
		t.Fatalf("algo=%q added=%d", m.algo, len(m.added))
	}
}

func TestHandleSkipsProcessedRun(t *testing.T) {
	m := newMemory()
	run := testRun(t, "run", "semgrep")
	m.addRun(run, finding(run, "f1", "a", ""))
	m.processed["run"] = true

	got := handle(t, newWorker(t, m), "run")

	if !got.Already || len(m.added) != 0 || len(m.members) != 0 {
		t.Fatalf("result=%+v added=%d members=%d", got, len(m.added), len(m.members))
	}
}

func TestHandlePropagatesRunError(t *testing.T) {
	m := newMemory()
	m.runErr = errBoom
	if _, err := newWorker(t, m).Handle(context.Background(), "tenant", "run"); !errors.Is(err, errBoom) {
		t.Fatalf("got %v", err)
	}
}

func TestNewRejectsMissingDeps(t *testing.T) {
	if _, err := worker.New(nil, nil, worker.Dedup{}); !errors.Is(err, worker.ErrInvalidConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestHandleJoinsDuplicateOfEarlierRun(t *testing.T) {
	m := newMemory()
	first := testRun(t, "run1", "trivy")
	second := testRun(t, "run2", "trivy")
	m.addRun(first, dependency(first, "f1", "a", "CVE-1", "pkg:x@1"))
	m.addRun(second, dependency(second, "f2", "b", "CVE-1", "pkg:x@1"), dependency(second, "f3", "c", "CVE-2", "pkg:y@1"))
	w := newWorker(t, m)

	handle(t, w, "run1")
	got := handle(t, w, "run2")

	if m.clusterOf["f2"] != m.clusterOf["f1"] || m.clusterOf["f3"] == m.clusterOf["f1"] {
		t.Fatalf("clusters: %+v", m.clusterOf)
	}
	if got.Cluster.Joined != 1 || got.Cluster.Created != 1 || got.Cluster.Verdicts[dedup.VerdictMerge] != 1 {
		t.Fatalf("stats: %+v", got.Cluster)
	}
}

func TestHandleClustersDuplicatesInsideOneRun(t *testing.T) {
	m := newMemory()
	run := testRun(t, "run", "trivy")
	m.addRun(run,
		dependency(run, "f1", "a", "CVE-1", "pkg:x@1"),
		dependency(run, "f2", "b", "CVE-1", "pkg:x@1"),
		dependency(run, "f3", "c", "CVE-2", "pkg:y@1"),
	)

	got := handle(t, newWorker(t, m), "run")

	if m.clusterOf["f1"] != m.clusterOf["f2"] || m.clusterOf["f3"] == m.clusterOf["f1"] {
		t.Fatalf("clusters: %+v", m.clusterOf)
	}
	if got.Cluster.Created != 2 || len(m.members) != 3 {
		t.Fatalf("stats: %+v members=%d", got.Cluster, len(m.members))
	}
}

func TestHandleDoesNotClusterFindingsWithoutFingerprints(t *testing.T) {
	m := newMemory()
	run := testRun(t, "run", "trivy")
	m.addRun(run, model.Finding{ID: "f1", Scope: run.Scope, Kind: model.KindSCA})

	got := handle(t, newWorker(t, m), "run")

	if len(m.members) != 0 || got.Unfingerprinted != 1 || got.Cluster.Created != 0 {
		t.Fatalf("members=%d result=%+v", len(m.members), got)
	}
}

func TestHandleSkipsCandidatesWithoutCluster(t *testing.T) {
	m := newMemory()
	old := testRun(t, "run0", "trivy")
	fresh := testRun(t, "run1", "trivy")
	m.addRun(old, dependency(old, "f0", "z", "CVE-1", "pkg:x@1"))
	m.addRun(fresh, dependency(fresh, "f1", "a", "CVE-1", "pkg:x@1"))
	w := newWorker(t, m)
	handle(t, w, "run0")
	delete(m.clusterOf, "f0")

	got := handle(t, w, "run1")

	if _, joined := m.clusterOf["f1"]; !joined || m.clusterOf["f1"] == m.clusterOf["f0"] {
		t.Fatalf("f1 must start its own cluster: %+v", m.clusterOf)
	}
	if got.Cluster.Unclustered == 0 || got.Cluster.Created != 1 {
		t.Fatalf("stats: %+v", got.Cluster)
	}
}
