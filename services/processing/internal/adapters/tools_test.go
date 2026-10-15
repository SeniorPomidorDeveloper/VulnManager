package adapters

import (
	"testing"

	"vulnmanager/modules/model"
)

func TestBuiltinSelectsSetByTool(t *testing.T) {
	registry, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"trivy":   "tool-uid@1+identity@1",
		"semgrep": "tool-uid@1+structural@1",
		"unknown": "tool-uid@1",
	}
	for tool, algo := range want {
		if got := registry.For(model.ToolName(tool)).AlgoVersion(); got != algo {
			t.Fatalf("%s: got %q, want %q", tool, got, algo)
		}
	}
}
