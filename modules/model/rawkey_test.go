package model

import "testing"

func TestRawKeyFor_TakesTenantFromScope(t *testing.T) {
	scope, err := NewScope("t1", "p1", "c1")
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}

	key := RawKeyFor(scope, "scan-1", "abcd")

	if key.TenantID != scope.TenantID {
		t.Fatalf("got tenant %q, want %q", key.TenantID, scope.TenantID)
	}
	if got, want := key.String(), "t1/scan-1/abcd"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
