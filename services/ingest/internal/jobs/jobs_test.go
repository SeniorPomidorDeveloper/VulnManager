package jobs

import (
	"context"
	"errors"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/modules/rawstore"
)

type fakeStore struct {
	limits map[model.TenantID]int64
	jobs   []rawstore.Key
}

func (f *fakeStore) MaxReportBytes(_ context.Context, tenantID model.TenantID) (int64, error) {
	limit, ok := f.limits[tenantID]
	if !ok {
		return 0, ErrTenantNotFound
	}
	return limit, nil
}

func (f *fakeStore) InsertJob(_ context.Context, _ model.Scope, rawKey rawstore.Key) error {
	f.jobs = append(f.jobs, rawKey)
	return nil
}

func newScope(t *testing.T, tenant model.TenantID) model.Scope {
	t.Helper()
	scope, err := model.NewScope(tenant, "product", "")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func TestEnqueue(t *testing.T) {
	tests := []struct {
		name     string
		tenant   model.TenantID
		size     int64
		wantErr  error
		wantJobs int
	}{
		{name: "below limit", tenant: "acme", size: 10, wantJobs: 1},
		{name: "exactly at limit", tenant: "acme", size: 100, wantJobs: 1},
		{name: "above limit", tenant: "acme", size: 101, wantErr: ErrReportTooLarge},
		{name: "unknown tenant", tenant: "other", size: 1, wantErr: ErrTenantNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{limits: map[model.TenantID]int64{"acme": 100}}
			scope := newScope(t, tc.tenant)
			key := rawstore.KeyFor(scope, "scan-1", "abc")

			err := NewEnqueuer(store).Enqueue(context.Background(), scope, key, tc.size)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got err=%v, want %v", err, tc.wantErr)
			}
			if len(store.jobs) != tc.wantJobs {
				t.Fatalf("got %d jobs, want %d", len(store.jobs), tc.wantJobs)
			}
		})
	}
}
