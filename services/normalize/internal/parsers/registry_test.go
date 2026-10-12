package parsers

import (
	"context"
	"errors"
	"io"
	"iter"
	"testing"
)

type stub struct {
	id    ParserID
	score SniffScore
}

func (s stub) ID() ParserID               { return s.id }
func (s stub) Version() ParserVersion     { return "1" }
func (s stub) Capabilities() Capabilities { return Capabilities{} }
func (s stub) Sniff([]byte) SniffScore    { return s.score }
func (s stub) Parse(context.Context, io.Reader, ScanMeta) iter.Seq2[RawFinding, error] {
	return func(func(RawFinding, error) bool) {}
}

func TestRegistry_RegisterRejectsDuplicates(t *testing.T) {
	registry := NewRegistry(stub{id: "fallback"})
	if err := registry.Register(stub{id: "sarif"}); err != nil {
		t.Fatal(err)
	}

	err := registry.Register(stub{id: "sarif"})

	if !errors.Is(err, ErrDuplicateParser) {
		t.Fatalf("got %v, want ErrDuplicateParser", err)
	}
}

func TestRegistry_Detect(t *testing.T) {
	tests := []struct {
		name    string
		parsers []stub
		want    ParserID
	}{
		{name: "highest score wins", parsers: []stub{{"a", 0.6}, {"b", 0.9}}, want: "b"},
		{name: "tie goes to the smaller id", parsers: []stub{{"b", 0.8}, {"a", 0.8}}, want: "a"},
		{name: "below threshold falls back", parsers: []stub{{"a", 0.5}, {"b", 0.2}}, want: "fallback"},
		{name: "empty registry falls back", want: "fallback"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewRegistry(stub{id: "fallback"})
			for _, p := range tc.parsers {
				if err := registry.Register(p); err != nil {
					t.Fatal(err)
				}
			}

			if got := registry.Detect([]byte("{}")).ID(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
