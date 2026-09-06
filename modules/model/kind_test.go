package model

import (
	"errors"
	"testing"
)

func TestParseKind(t *testing.T) {
	cases := []struct {
		in      string
		want    Kind
		wantErr error
	}{
		{"sast", KindSAST, nil},
		{"dast", KindDAST, nil},
		{"sca", KindSCA, nil},
		{"secret", KindSecret, nil},
		{"iac", KindIaC, nil},
		{"container", KindContainer, nil},
		{"unknown", KindUnknown, nil},
		{"nonsense", KindUnknown, ErrUnknownKind},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := ParseKind(c.in)
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("got err=%v, want %v", err, c.wantErr)
			}
		})
	}
}
