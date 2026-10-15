package fingerprint_test

import (
	"encoding/json"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/fingerprint"
	"vulnmanager/services/processing/internal/fingerprint/fptest"
)

func scope(t *testing.T, product model.ProductID) model.Scope {
	t.Helper()
	result, err := model.NewScope("tenant", product, "")
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func sast(t *testing.T) model.Finding {
	t.Helper()
	return model.Finding{
		Scope:         scope(t, "product"),
		ToolFindingID: "tool-id",
		Kind:          model.KindSAST,
		RuleID:        "rule.sqli",
		Provenance:    model.Provenance{Tool: "semgrep"},
		Location:      json.RawMessage(`{"uri":"src/db.go","start_line":10,"snippet":"db.Query(\"x\" + y)"}`),
	}
}

func TestContracts(t *testing.T) {
	cases := map[string]struct {
		strategy   fingerprint.Strategy
		applicable func(*testing.T) model.Finding
	}{
		"tool-uid": {fingerprint.ToolUID{}, sast},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fptest.RunContractSuite(t, tc.strategy, tc.applicable(t))
		})
	}
}

func fingerprintOf(t *testing.T, strategy fingerprint.Strategy, finding model.Finding) fingerprint.Fingerprint {
	t.Helper()
	got, ok := strategy.Fingerprint(finding)
	if !ok {
		t.Fatalf("%s: not applicable", strategy.ID())
	}
	return got
}

func TestToolUIDDependsOnToolScopeAndID(t *testing.T) {
	base := sast(t)
	want := fingerprintOf(t, fingerprint.ToolUID{}, base)

	changed := map[string]func(*model.Finding){
		"tool":  func(f *model.Finding) { f.Provenance.Tool = "other" },
		"scope": func(f *model.Finding) { f.Scope = scope(t, "other") },
		"id":    func(f *model.Finding) { f.ToolFindingID = "other" },
	}
	for name, mutate := range changed {
		t.Run(name, func(t *testing.T) {
			finding := base
			mutate(&finding)
			if got := fingerprintOf(t, fingerprint.ToolUID{}, finding); got == want {
				t.Fatalf("%s change must change fingerprint", name)
			}
		})
	}
}

func TestSet(t *testing.T) {
	set, err := fingerprint.NewSet(fingerprint.ToolUID{})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("algo version names participants", func(t *testing.T) {
		if got, want := set.AlgoVersion(), "tool-uid@1"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("computes applicable levels", func(t *testing.T) {
		got, diagnostics := set.Compute(sast(t))
		if len(got) != 1 || got[0].Level != fingerprint.LevelToolUID || len(diagnostics) != 0 {
			t.Fatalf("got %+v, %+v", got, diagnostics)
		}
	})

	t.Run("warns when nothing is computable", func(t *testing.T) {
		got, diagnostics := set.Compute(model.Finding{})
		if len(got) != 0 || !diagnostics.Has("no_fingerprint") {
			t.Fatalf("got %+v, %+v", got, diagnostics)
		}
	})

	t.Run("rejects duplicate level", func(t *testing.T) {
		_, err := fingerprint.NewSet(fingerprint.ToolUID{}, fingerprint.ToolUID{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestRegistry(t *testing.T) {
	fallback, _ := fingerprint.NewSet()
	trivy, _ := fingerprint.NewSet(fingerprint.ToolUID{})
	registry := fingerprint.NewRegistry(fallback)

	if err := registry.Register("trivy", trivy); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("trivy", trivy); err == nil {
		t.Fatal("duplicate tool must be rejected")
	}
	if got := registry.For("trivy").AlgoVersion(); got != trivy.AlgoVersion() {
		t.Fatalf("got %q", got)
	}
	if got := registry.For("unknown").AlgoVersion(); got != fallback.AlgoVersion() {
		t.Fatalf("got %q", got)
	}
}
