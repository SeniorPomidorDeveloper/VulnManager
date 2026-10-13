package normalizers

import (
	"context"
	"errors"
	"testing"

	"vulnmanager/modules/model"
)

func TestProfiles_ToolChainOverridesDefault(t *testing.T) {
	var visited []NormalizerID
	registry := NewRegistry()
	for _, id := range []NormalizerID{"base", "custom"} {
		if err := registry.Register(stub{id: id, visited: &visited}); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}
	profiles, err := registry.Profiles(ProfileSpec{
		Default: []NormalizerID{"base"},
		ByTool:  map[model.ToolName][]NormalizerID{"newscanner": {"base", "custom"}},
	})
	if err != nil {
		t.Fatalf("profiles: %v", err)
	}

	cases := []struct {
		tool model.ToolName
		want string
	}{
		{"trivy", "base@1"},
		{"newscanner", "base@1+custom@1"},
	}
	for _, c := range cases {
		chain := profiles.For(c.tool)
		if chain.Version() != c.want {
			t.Fatalf("%s: version %q, want %q", c.tool, chain.Version(), c.want)
		}
		if err := chain.Apply(context.Background(), &model.Finding{}); err != nil {
			t.Fatalf("%s: apply: %v", c.tool, err)
		}
	}
}

func TestRegistry_ProfilesRejectUnknownNormalizer(t *testing.T) {
	registry := NewRegistry()
	_, err := registry.Profiles(ProfileSpec{
		ByTool: map[model.ToolName][]NormalizerID{"newscanner": {"missing"}},
	})
	if !errors.Is(err, ErrUnknownNormalizer) {
		t.Fatalf("err=%v", err)
	}
}
