package normalizers_test

import (
	"context"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
)

func TestToolNormalizers(t *testing.T) {
	cases := []struct {
		name        string
		build       func() (normalizers.Normalizer, error)
		in          model.Finding
		wantSev     model.Severity
		wantVuln    model.VulnID
		wantPURL    model.PURL
		wantPath    string
		wantVersion normalizers.NormalizerVersion
	}{
		{
			"trivy", normalizers.NewTrivy,
			model.Finding{SeverityRaw: "HIGH", VulnIDRaw: "cve-2026-3449", PURLRaw: "pkg:npm/%40Scope/Pkg@1", Location: []byte(`{"target":"/app/package-lock.json"}`)},
			model.SeverityHigh,
			model.VulnID{Source: "cve", Value: "CVE-2026-3449"},
			"pkg:npm/%40scope/pkg@1",
			`{"target":"package-lock.json"}`,
			"severity@1+vulnid@1+component@1+path@1",
		},
		{
			"sarif", normalizers.NewSARIF,
			model.Finding{SeverityRaw: "error", Location: []byte(`{"uri":"/src/a.go"}`)},
			model.SeverityHigh,
			model.VulnID{},
			"",
			`{"uri":"a.go"}`,
			"severity@1+path@1",
		},
		{
			"generic", normalizers.NewGeneric,
			model.Finding{SeverityRaw: "warning", Location: []byte(`{"uri":"/app/a.go"}`)},
			model.SeverityMedium,
			model.VulnID{},
			"",
			`{"uri":"a.go"}`,
			"severity@1+vulnid@1+path@1",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, err := c.build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			got := c.in
			if err := n.Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if got.Severity != c.wantSev || string(got.Location) != c.wantPath || n.Version() != c.wantVersion {
				t.Fatalf("severity %v location %s version %s", got.Severity, got.Location, n.Version())
			}
			if got.Component.PURL != c.wantPURL {
				t.Fatalf("component %+v, want purl %q", got.Component, c.wantPURL)
			}
			if got.VulnID != c.wantVuln {
				t.Fatalf("vuln id %+v, want %+v", got.VulnID, c.wantVuln)
			}
		})
	}
}
