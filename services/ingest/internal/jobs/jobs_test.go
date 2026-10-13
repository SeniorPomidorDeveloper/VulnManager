package jobs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"

	"vulnmanager/modules/model"
)

type fakeStore struct {
	limits map[model.TenantID]int64
	jobs   map[string]Job
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		limits: map[model.TenantID]int64{"acme": 100},
		jobs:   map[string]Job{},
	}
}

func jobKey(scope model.Scope, tool model.ToolName, sha string) string {
	return string(scope.Key()) + "/" + string(tool) + "/" + sha
}

func (f *fakeStore) MaxReportBytes(_ context.Context, tenantID model.TenantID) (int64, error) {
	limit, ok := f.limits[tenantID]
	if !ok {
		return 0, ErrTenantNotFound
	}
	return limit, nil
}

func (f *fakeStore) FindJob(_ context.Context, scope model.Scope, tool model.ToolName, sha string) (Job, bool, error) {
	job, ok := f.jobs[jobKey(scope, tool, sha)]
	return job, ok, nil
}

func (f *fakeStore) InsertJob(_ context.Context, scope model.Scope, tool model.ToolName, key model.RawKey) (uuid.UUID, bool, error) {
	k := jobKey(scope, tool, key.SHA256)
	if _, ok := f.jobs[k]; ok {
		return uuid.Nil, false, nil
	}
	job := Job{ID: uuid.New(), ScanID: key.ScanID, State: StatePending}
	f.jobs[k] = job
	return job.ID, true, nil
}

type fakePublisher struct {
	events []Event
	err    error
}

func (f *fakePublisher) Publish(_ context.Context, event Event) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, event)
	return nil
}

type fakeRaw struct {
	puts int
}

func (f *fakeRaw) Put(_ context.Context, _ model.RawKey, r io.Reader, _ int64) error {
	f.puts++
	_, err := io.Copy(io.Discard, r)
	return err
}

func newScope(t *testing.T, tenant model.TenantID) model.Scope {
	t.Helper()
	scope, err := model.NewScope(tenant, "product", "")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func TestAccept_Limits(t *testing.T) {
	tests := []struct {
		name    string
		tenant  model.TenantID
		size    int
		wantErr error
	}{
		{name: "below limit", tenant: "acme", size: 10},
		{name: "exactly at limit", tenant: "acme", size: 100},
		{name: "above limit", tenant: "acme", size: 101, wantErr: ErrReportTooLarge},
		{name: "unknown tenant", tenant: "other", size: 1, wantErr: ErrTenantNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := &fakeRaw{}
			e := NewEnqueuer(newFakeStore(), raw, &fakePublisher{})

			_, err := e.Accept(context.Background(), Report{
				Scope: newScope(t, tc.tenant), Tool: "trivy", ScanID: "scan-1", Body: bytes.Repeat([]byte("a"), tc.size),
			})

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got err=%v, want %v", err, tc.wantErr)
			}
			wantPuts := 0
			if tc.wantErr == nil {
				wantPuts = 1
			}
			if raw.puts != wantPuts {
				t.Fatalf("got %d puts, want %d", raw.puts, wantPuts)
			}
		})
	}
}

func TestAccept_DuplicateReturnsFirstScanID(t *testing.T) {
	raw := &fakeRaw{}
	e := NewEnqueuer(newFakeStore(), raw, &fakePublisher{})
	scope := newScope(t, "acme")

	first, err := e.Accept(context.Background(), Report{Scope: scope, Tool: "trivy", ScanID: "scan-1", Body: []byte("report")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.Accept(context.Background(), Report{Scope: scope, Tool: "trivy", ScanID: "scan-2", Body: []byte("report")})
	if err != nil {
		t.Fatal(err)
	}

	if first.ScanID != "scan-1" || second.ScanID != "scan-1" {
		t.Fatalf("got scan ids %q and %q, want both scan-1", first.ScanID, second.ScanID)
	}
	if first.SHA256 != second.SHA256 {
		t.Fatalf("sha differs: %q vs %q", first.SHA256, second.SHA256)
	}
	if raw.puts != 1 {
		t.Fatalf("got %d puts, want 1", raw.puts)
	}
}

func TestAccept_DifferentToolIsNotDuplicate(t *testing.T) {
	raw := &fakeRaw{}
	e := NewEnqueuer(newFakeStore(), raw, &fakePublisher{})
	scope := newScope(t, "acme")

	_, err := e.Accept(context.Background(), Report{Scope: scope, Tool: "trivy", ScanID: "scan-1", Body: []byte("report")})
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.Accept(context.Background(), Report{Scope: scope, Tool: "semgrep", ScanID: "scan-2", Body: []byte("report")})
	if err != nil {
		t.Fatal(err)
	}

	if other.ScanID != "scan-2" {
		t.Fatalf("got scan id %q, want scan-2", other.ScanID)
	}
}

func TestAccept_PublishesEventWithJobID(t *testing.T) {
	store, publisher := newFakeStore(), &fakePublisher{}
	e := NewEnqueuer(store, &fakeRaw{}, publisher)
	scope := newScope(t, "acme")

	accepted, err := e.Accept(context.Background(), Report{Scope: scope, Tool: "trivy", ScanID: "scan-1", Body: []byte("report")})
	if err != nil {
		t.Fatal(err)
	}

	job := store.jobs[jobKey(scope, "trivy", accepted.SHA256)]
	want := Event{JobID: job.ID, Scope: scope, Tool: "trivy", RawKey: model.RawKeyFor(scope, "scan-1", accepted.SHA256)}
	if len(publisher.events) != 1 || publisher.events[0] != want {
		t.Fatalf("got events %+v, want [%+v]", publisher.events, want)
	}
}

func TestAccept_PublishFailureIsRetriedOnRepeat(t *testing.T) {
	raw, publisher := &fakeRaw{}, &fakePublisher{err: errors.New("broker down")}
	e := NewEnqueuer(newFakeStore(), raw, publisher)
	report := Report{Scope: newScope(t, "acme"), Tool: "trivy", ScanID: "scan-1", Body: []byte("report")}

	_, err := e.Accept(context.Background(), report)
	if !errors.Is(err, ErrNotPublished) {
		t.Fatalf("got err=%v, want ErrNotPublished", err)
	}

	publisher.err = nil
	retried, err := e.Accept(context.Background(), report)

	if err != nil || retried.ScanID != "scan-1" {
		t.Fatalf("retry: accepted=%+v err=%v", retried, err)
	}
	if len(publisher.events) != 1 || raw.puts != 1 {
		t.Fatalf("got %d events and %d puts, want 1 and 1", len(publisher.events), raw.puts)
	}
}

func TestAccept_FinishedJobIsNotPublishedAgain(t *testing.T) {
	store, publisher := newFakeStore(), &fakePublisher{}
	e := NewEnqueuer(store, &fakeRaw{}, publisher)
	scope := newScope(t, "acme")
	report := Report{Scope: scope, Tool: "trivy", ScanID: "scan-1", Body: []byte("report")}
	accepted, err := e.Accept(context.Background(), report)
	if err != nil {
		t.Fatal(err)
	}
	key := jobKey(scope, "trivy", accepted.SHA256)
	finished := store.jobs[key]
	finished.State = "done"
	store.jobs[key] = finished

	if _, err := e.Accept(context.Background(), report); err != nil {
		t.Fatal(err)
	}

	if len(publisher.events) != 1 {
		t.Fatalf("got %d events, want 1", len(publisher.events))
	}
}
