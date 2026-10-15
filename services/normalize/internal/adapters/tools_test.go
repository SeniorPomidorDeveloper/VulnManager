package adapters

import (
	"context"
	"testing"

	"vulnmanager/modules/model"
)

func TestToolNormalizers(t *testing.T) {
	cases := []struct {
		name        string
		build       factory
		in          model.Finding
		wantSev     model.Severity
		wantVuln    model.VulnID
		wantPURL    model.PURL
		wantPath    string
		wantVersion string
	}{
		{
			"trivy", trivy,
			model.Finding{
				SeverityRaw: "HIGH", VulnIDRaw: "cve-2026-3449", PURLRaw: "pkg:npm/%40Scope/Pkg@1",
				Location: []byte(`{"target":"/app/package-lock.json"}`),
				CVSSRaw:  []model.CVSSCandidate{{Source: "nvd", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			},
			model.SeverityCritical,
			model.VulnID{Source: "cve", Value: "CVE-2026-3449"},
			"pkg:npm/%40scope/pkg@1",
			`{"target":"package-lock.json"}`,
			"cvss@1+severity@2(cvss>label;cvss=nvd,ghsa,redhat,bitnami)+vulnid@1+component@1+cwe@1+path@1",
		},
		{
			"semgrep", semgrep,
			model.Finding{SeverityRaw: "note", ScannerScore: scoreOf(9.1), Location: []byte(`{"uri":"/src/a.go"}`)},
			model.SeverityCritical,
			model.VulnID{},
			"", `{"uri":"a.go"}`,
			"severity@2(score>label)+cwe@1+path@1",
		},
		{
			"generic", generic,
			model.Finding{SeverityRaw: "warning", Location: []byte(`{"uri":"/app/a.go"}`)},
			model.SeverityMedium,
			model.VulnID{},
			"", `{"uri":"a.go"}`,
			"severity@2(label)+vulnid@1+path@1",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			adapter, err := c.build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			got := c.in
			if err := adapter.Normalizer.Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if got.Severity != c.wantSev || string(got.Location) != c.wantPath || string(adapter.Normalizer.Version()) != c.wantVersion {
				t.Fatalf("severity %v location %s version %s", got.Severity, got.Location, adapter.Normalizer.Version())
			}
			if got.Component.PURL != c.wantPURL || got.VulnID != c.wantVuln {
				t.Fatalf("component %+v vuln id %+v", got.Component, got.VulnID)
			}
		})
	}
}

func scoreOf(value model.Score) *model.Score {
	return &value
}
