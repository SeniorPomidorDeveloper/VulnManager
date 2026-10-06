package rawstore

import (
	"testing"

	"vulnmanager/modules/model"
)

func TestKeyFor_TakesTenantFromScope(t *testing.T) {
	scope, err := model.NewScope("t1", "p1", "c1")
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}

	key := KeyFor(scope, "scan-1", "abcd")

	if key.TenantID != scope.TenantID {
		t.Fatalf("got tenant %q, want %q", key.TenantID, scope.TenantID)
	}
	if got, want := key.String(), "t1/scan-1/abcd"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
