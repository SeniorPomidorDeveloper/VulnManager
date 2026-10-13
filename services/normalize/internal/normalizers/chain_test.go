package normalizers

import (
	"context"
	"errors"
	"testing"

	"vulnmanager/modules/model"
)

type stub struct {
	id      NormalizerID
	kind    model.Kind
	err     error
	visited *[]NormalizerID
}

func (s stub) ID() NormalizerID           { return s.id }
func (s stub) Version() NormalizerVersion { return "1" }

func (s stub) Applies(kind model.Kind) bool {
	return s.kind == model.KindUnknown || s.kind == kind
}

func (s stub) Normalize(context.Context, *model.Finding) error {
	*s.visited = append(*s.visited, s.id)
	return s.err
}

func TestChain_AppliesInOrderAndSkipsForeignKinds(t *testing.T) {
	var visited []NormalizerID
	chain, err := NewChain(
		stub{id: "a", visited: &visited},
		stub{id: "b", kind: model.KindSAST, visited: &visited},
		stub{id: "c", visited: &visited},
	)
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	if err := chain.Apply(context.Background(), &model.Finding{Kind: model.KindSCA}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(visited) != 2 || visited[0] != "a" || visited[1] != "c" {
		t.Fatalf("visited %v, want [a c]", visited)
	}
	if got := chain.Version(); got != "a@1+b@1+c@1" {
		t.Fatalf("version %q", got)
	}
}

func TestChain_StopsOnErrorAndNamesStep(t *testing.T) {
	var visited []NormalizerID
	boom := errors.New("boom")
	chain, err := NewChain(
		stub{id: "a", err: boom, visited: &visited},
		stub{id: "b", visited: &visited},
	)
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	err = chain.Apply(context.Background(), &model.Finding{})
	if !errors.Is(err, boom) || len(visited) != 1 {
		t.Fatalf("err=%v visited=%v", err, visited)
	}
}

func TestNewChain_RejectsDuplicates(t *testing.T) {
	var visited []NormalizerID
	_, err := NewChain(stub{id: "a", visited: &visited}, stub{id: "a", visited: &visited})
	if !errors.Is(err, ErrDuplicateNormalizer) {
		t.Fatalf("err=%v", err)
	}
}

func TestRegistry(t *testing.T) {
	var visited []NormalizerID
	registry := NewRegistry()
	if err := registry.Register(stub{id: "a", visited: &visited}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := registry.Register(stub{id: "a", visited: &visited}); !errors.Is(err, ErrDuplicateNormalizer) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := registry.Chain("a", "missing"); !errors.Is(err, ErrUnknownNormalizer) {
		t.Fatalf("unknown: %v", err)
	}
	chain, err := registry.Chain("a")
	if err != nil || chain.Version() != "a@1" {
		t.Fatalf("chain=%q err=%v", chain.Version(), err)
	}
}
