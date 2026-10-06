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

func TestKind_ZeroValueIsUnknown(t *testing.T) {
	var k Kind
	if k != KindUnknown {
		t.Fatalf("zero Kind = %v, want KindUnknown", k)
	}
	if k.String() != "unknown" {
		t.Fatalf("got %q, want %q", k.String(), "unknown")
	}
}

func TestKind_StringRoundTrip(t *testing.T) {
	for _, k := range []Kind{KindSAST, KindDAST, KindSCA, KindSecret, KindIaC, KindContainer, KindUnknown} {
		got, err := ParseKind(k.String())
		if err != nil || got != k {
			t.Fatalf("round trip of %v: got %v, err=%v", k, got, err)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in      string
		want    Severity
		wantErr error
	}{
		{"critical", SeverityCritical, nil},
		{"high", SeverityHigh, nil},
		{"medium", SeverityMedium, nil},
		{"low", SeverityLow, nil},
		{"info", SeverityInfo, nil},
		{"unknown", SeverityUnknown, nil},
		{"nonsense", SeverityUnknown, ErrUnknownSeverity},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := ParseSeverity(c.in)
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("got err=%v, want %v", err, c.wantErr)
			}
		})
	}
}

func TestSeverity_ZeroValueIsUnknown(t *testing.T) {
	var s Severity
	if s != SeverityUnknown {
		t.Fatalf("zero Severity = %v, want SeverityUnknown", s)
	}
	if s.String() != "unknown" {
		t.Fatalf("got %q, want %q", s.String(), "unknown")
	}
}
