package normalizers_test

import (
	"context"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/normalizers/normtest"
)

var testScales = normalizers.SeverityScales{
	ByTool: map[model.ToolName]normalizers.SeverityScale{
		"semgrep": {"error": model.SeverityHigh, "warning": model.SeverityMedium},
	},
	Default: normalizers.SeverityScale{
		"critical": model.SeverityCritical,
		"high":     model.SeverityHigh,
		"low":      model.SeverityLow,
	},
}

func finding(tool model.ToolName, raw model.SeverityRaw) model.Finding {
	return model.Finding{
		ToolFindingID: model.ToolFindingID(string(tool) + "/" + string(raw)),
		SeverityRaw:   raw,
		Provenance:    model.Provenance{Tool: tool},
	}
}

func TestSeverity_Normalize(t *testing.T) {
	cases := []struct {
		name string
		in   model.Finding
		want model.Severity
	}{
		{"tool scale", finding("semgrep", "ERROR"), model.SeverityHigh},
		{"tool scale ignores default labels", finding("semgrep", "critical"), model.SeverityUnknown},
		{"default scale", finding("trivy", " Critical "), model.SeverityCritical},
		{"unknown label", finding("trivy", "weird"), model.SeverityUnknown},
		{"empty label", finding("trivy", ""), model.SeverityUnknown},
	}
	n := normalizers.NewSeverity(testScales)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.in
			if err := n.Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalizers: %v", err)
			}
			if got.Severity != c.want {
				t.Fatalf("got %v, want %v", got.Severity, c.want)
			}
			if wantDiag := c.want == model.SeverityUnknown; got.Diagnostics.Has("unknown_severity") != wantDiag {
				t.Fatalf("diagnostics %+v", got.Diagnostics)
			}
		})
	}
}

func TestSeverity_Suite(t *testing.T) {
	normtest.Suite(t, normalizers.NewSeverity(testScales), []model.Finding{
		finding("semgrep", "error"),
		finding("trivy", "HIGH"),
		finding("trivy", "weird"),
	})
}
