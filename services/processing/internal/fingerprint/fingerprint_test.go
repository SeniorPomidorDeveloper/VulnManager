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

func sca(t *testing.T) model.Finding {
	t.Helper()
	return model.Finding{
		Scope:         scope(t, "product"),
		ToolFindingID: "CVE-2024-1\x00pkg",
		Kind:          model.KindSCA,
		Provenance:    model.Provenance{Tool: "trivy"},
		VulnID:        model.VulnID{Source: "cve", Value: "CVE-2024-1"},
		Component:     model.Component{PURL: "pkg:golang/x/y@1.0.0"},
		Location:      json.RawMessage(`{"target":"go.mod"}`),
	}
}

func TestContracts(t *testing.T) {
	cases := map[string]struct {
		strategy   fingerprint.Strategy
		applicable func(*testing.T) model.Finding
	}{
		"tool-uid":   {fingerprint.ToolUID{}, sast},
		"identity":   {fingerprint.Identity{}, sca},
		"structural": {fingerprint.Structural{}, sast},
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

func TestIdentity(t *testing.T) {
	base := sca(t)
	want := fingerprintOf(t, fingerprint.Identity{}, base)

	changed := map[string]func(*model.Finding){
		"vuln":      func(f *model.Finding) { f.VulnID.Value = "CVE-2024-2" },
		"component": func(f *model.Finding) { f.Component.PURL = "pkg:golang/x/y@1.0.1" },
		"path":      func(f *model.Finding) { f.Location = json.RawMessage(`{"target":"other/go.mod"}`) },
		"scope":     func(f *model.Finding) { f.Scope = scope(t, "other") },
		"kind":      func(f *model.Finding) { f.Kind = model.KindContainer },
	}
	for name, mutate := range changed {
		t.Run(name, func(t *testing.T) {
			finding := base
			mutate(&finding)
			if got := fingerprintOf(t, fingerprint.Identity{}, finding); got == want {
				t.Fatalf("%s change must change fingerprint", name)
			}
		})
	}

	t.Run("without vuln id", func(t *testing.T) {
		finding := base
		finding.VulnID = model.VulnID{}
		if _, ok := (fingerprint.Identity{}).Fingerprint(finding); ok {
			t.Fatal("finding without vuln id must be skipped")
		}
	})

	t.Run("component fields replace missing purl", func(t *testing.T) {
		finding := base
		finding.Component = model.Component{Type: "golang", Name: "y", Version: "1.0.0"}
		if got := fingerprintOf(t, fingerprint.Identity{}, finding); got == want {
			t.Fatal("different component form must differ")
		}
	})
}

func TestStructural(t *testing.T) {
	base := sast(t)
	want := fingerprintOf(t, fingerprint.Structural{}, base)

	t.Run("survives line shift and reformatting", func(t *testing.T) {
		finding := base
		finding.Location = json.RawMessage(`{"uri":"src/db.go","start_line":42,"snippet":"  db.Query( \"x\"  +\n y )"}`)
		if got := fingerprintOf(t, fingerprint.Structural{}, finding); got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	changed := map[string]func(*model.Finding){
		"rule": func(f *model.Finding) { f.RuleID = "rule.other" },
		"path": func(f *model.Finding) {
			f.Location = json.RawMessage(`{"uri":"src/other.go","snippet":"db.Query(\"x\" + y)"}`)
		},
		"snippet": func(f *model.Finding) { f.Location = json.RawMessage(`{"uri":"src/db.go","snippet":"db.Exec(z)"}`) },
		"scope":   func(f *model.Finding) { f.Scope = scope(t, "other") },
	}
	for name, mutate := range changed {
		t.Run(name, func(t *testing.T) {
			finding := base
			mutate(&finding)
			if got := fingerprintOf(t, fingerprint.Structural{}, finding); got == want {
				t.Fatalf("%s change must change fingerprint", name)
			}
		})
	}

	skipped := map[string]string{
		"no snippet":       `{"uri":"src/db.go","start_line":10}`,
		"no path":          `{"snippet":"x"}`,
		"broken location":  `{`,
		"blank snippet":    `{"uri":"src/db.go","snippet":"  \n "}`,
		"unknown location": `[]`,
	}
	for name, raw := range skipped {
		t.Run(name, func(t *testing.T) {
			finding := base
			finding.Location = json.RawMessage(raw)
			if _, ok := (fingerprint.Structural{}).Fingerprint(finding); ok {
				t.Fatal("must be skipped")
			}
		})
	}
}

func TestSet(t *testing.T) {
	set, err := fingerprint.NewSet(fingerprint.ToolUID{}, fingerprint.Identity{}, fingerprint.Structural{})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("algo version lists participants in order", func(t *testing.T) {
		if got, want := set.AlgoVersion(), "tool-uid@1+identity@1+structural@1"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("computes applicable levels and reports skipped", func(t *testing.T) {
		got, diagnostics := set.Compute(sast(t))
		if len(got) != 2 || got[0].Level != fingerprint.LevelToolUID || got[1].Level != fingerprint.LevelStructural {
			t.Fatalf("got %+v", got)
		}
		if !diagnostics.Has("fingerprint_level_skipped") || diagnostics.Has("no_fingerprint") {
			t.Fatalf("diagnostics: %+v", diagnostics)
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
	fallback, _ := fingerprint.NewSet(fingerprint.ToolUID{})
	trivy, _ := fingerprint.NewSet(fingerprint.ToolUID{}, fingerprint.Identity{})
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

func TestLineOf(t *testing.T) {
	tests := map[string]struct {
		location string
		want     int
	}{
		"line given":   {`{"uri":"a.go","start_line":42}`, 42},
		"line missing": {`{"uri":"a.go"}`, 0},
		"negative":     {`{"uri":"a.go","start_line":-3}`, 0},
		"broken json":  {`{`, 0},
		"no location":  {``, 0},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			finding := model.Finding{Location: json.RawMessage(tc.location)}
			if got := fingerprint.LineOf(finding); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}
