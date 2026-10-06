package jobs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/modules/rawstore"
)

type fakeStore struct {
	limits map[model.TenantID]int64
	jobs   map[string]model.ScanID
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		limits: map[model.TenantID]int64{"acme": 100},
		jobs:   map[string]model.ScanID{},
	}
}

func jobKey(scope model.Scope, tool, sha string) string {
	return string(scope.Key()) + "/" + tool + "/" + sha
}

func (f *fakeStore) MaxReportBytes(_ context.Context, tenantID model.TenantID) (int64, error) {
	limit, ok := f.limits[tenantID]
	if !ok {
		return 0, ErrTenantNotFound
	}
	return limit, nil
}

func (f *fakeStore) FindScanID(_ context.Context, scope model.Scope, tool, sha string) (model.ScanID, bool, error) {
	id, ok := f.jobs[jobKey(scope, tool, sha)]
	return id, ok, nil
}

func (f *fakeStore) InsertJob(_ context.Context, scope model.Scope, tool string, key rawstore.Key) (bool, error) {
	k := jobKey(scope, tool, key.SHA256)
	if _, ok := f.jobs[k]; ok {
		return false, nil
	}
	f.jobs[k] = key.ScanID
	return true, nil
}

type fakeRaw struct {
	puts int
}

func (f *fakeRaw) Put(_ context.Context, _ rawstore.Key, r io.Reader, _ int64) error {
	f.puts++
	_, err := io.Copy(io.Discard, r)
	return err
}

func (f *fakeRaw) Get(context.Context, rawstore.Key) (io.ReadCloser, error) {
	return nil, rawstore.ErrNotFound
}

func (f *fakeRaw) Stat(context.Context, rawstore.Key) (rawstore.Info, error) {
	return rawstore.Info{}, rawstore.ErrNotFound
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
			e := NewEnqueuer(newFakeStore(), raw)

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
	e := NewEnqueuer(newFakeStore(), raw)
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
	e := NewEnqueuer(newFakeStore(), raw)
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
