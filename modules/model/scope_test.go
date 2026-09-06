package model

import (
	"errors"
	"testing"
)

func TestNewScope_Validation(t *testing.T) {
	cases := []struct {
		name    string
		tenant  string
		product string
		wantErr error
	}{
		{"empty tenant", "", "p1", ErrEmptyTenant},
		{"empty product", "t1", "", ErrEmptyProduct},
		{"valid", "t1", "p1", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewScope(c.tenant, c.product, "")
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("got err=%v, want %v", err, c.wantErr)
			}
		})
	}
}

func TestScope_Key_Deterministic(t *testing.T) {
	s1, _ := NewScope("t1", "p1", "c1")
	s2, _ := NewScope("t1", "p1", "c1")
	if s1.Key() != s2.Key() {
		t.Fatalf("same inputs produced different keys: %q vs %q", s1.Key(), s2.Key())
	}
}

func TestScope_Key_DiffersByInput(t *testing.T) {
	s1, _ := NewScope("t1", "p1", "c1")
	s2, _ := NewScope("t1", "p1", "c2")
	if s1.Key() == s2.Key() {
		t.Fatalf("different inputs produced the same key: %q", s1.Key())
	}
}
