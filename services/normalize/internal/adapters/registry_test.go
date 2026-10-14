package adapters_test

import (
	"errors"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/adapters"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/parsers"
)

func testRegistry(t *testing.T) *adapters.Registry {
	t.Helper()
	chain, err := normalizers.NewChain()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := adapters.New(
		map[model.ToolName]adapters.Adapter{
			"semgrep": {Parser: parsers.NewSARIF(), Normalizer: chain},
			"trivy":   {Parser: parsers.NewTrivy(), Normalizer: chain},
		},
		adapters.Adapter{Parser: parsers.NewGenericJSON(), Normalizer: chain},
	)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestResolve(t *testing.T) {
	cases := []struct {
		tool       model.ToolName
		wantParser parsers.ParserID
		wantDiag   bool
	}{
		{"semgrep", "sarif", false},
		{"trivy", "trivy", false},
		{"codeql", "generic-json", true},
		{"", "generic-json", true},
	}
	registry := testRegistry(t)
	for _, c := range cases {
		t.Run(string(c.tool), func(t *testing.T) {
			got := registry.Resolve(c.tool)
			if got.Adapter.Parser.ID() != c.wantParser {
				t.Fatalf("parser %q, want %q", got.Adapter.Parser.ID(), c.wantParser)
			}
			if got.Diagnostics.Has("unknown_tool") != c.wantDiag {
				t.Fatalf("diagnostics %+v", got.Diagnostics)
			}
		})
	}
}

func TestNew_RejectsIncompleteAdapters(t *testing.T) {
	chain, _ := normalizers.NewChain()
	complete := adapters.Adapter{Parser: parsers.NewSARIF(), Normalizer: chain}
	cases := map[string]struct {
		tools    map[model.ToolName]adapters.Adapter
		fallback adapters.Adapter
	}{
		"fallback":    {nil, adapters.Adapter{Parser: parsers.NewGenericJSON()}},
		"tool parser": {map[model.ToolName]adapters.Adapter{"x": {Normalizer: chain}}, complete},
		"tool chain":  {map[model.ToolName]adapters.Adapter{"x": {Parser: parsers.NewSARIF()}}, complete},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := adapters.New(c.tools, c.fallback); !errors.Is(err, adapters.ErrIncompleteAdapter) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestBuiltin_ResolvesRegisteredTools(t *testing.T) {
	registry, err := adapters.Builtin()
	if err != nil {
		t.Fatalf("builtin: %v", err)
	}
	for tool, want := range map[model.ToolName]parsers.ParserID{"trivy": "trivy", "semgrep": "sarif"} {
		got := registry.Resolve(tool)
		if got.Adapter.Parser.ID() != want || len(got.Diagnostics) != 0 {
			t.Fatalf("%s: parser %q diagnostics %+v", tool, got.Adapter.Parser.ID(), got.Diagnostics)
		}
	}
}
