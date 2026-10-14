package normalizers_test

import (
	"context"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/normalizers/normtest"
)

var testScale = normalizers.SeverityScale{
	"error":    model.SeverityHigh,
	"warning":  model.SeverityMedium,
	"critical": model.SeverityCritical,
}

func finding(raw model.SeverityRaw) model.Finding {
	return model.Finding{ToolFindingID: model.ToolFindingID("id/" + string(raw)), SeverityRaw: raw}
}

func TestSeverity_Normalize(t *testing.T) {
	cases := []struct {
		name string
		in   model.Finding
		want model.Severity
	}{
		{"label", finding("ERROR"), model.SeverityHigh},
		{"trimmed", finding(" Critical "), model.SeverityCritical},
		{"unknown label", finding("weird"), model.SeverityUnknown},
		{"empty label", finding(""), model.SeverityUnknown},
	}
	n := normalizers.NewSeverity(testScale)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.in
			if err := n.Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
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
	normtest.Suite(t, normalizers.NewSeverity(testScale), []model.Finding{
		finding("error"),
		finding("CRITICAL"),
		finding("weird"),
	})
}

func TestStandardScales(t *testing.T) {
	merged := normalizers.MergeScales(normalizers.LabelScale(), normalizers.SARIFLevelScale())
	for label, want := range map[model.SeverityRaw]model.Severity{
		"critical": model.SeverityCritical, "moderate": model.SeverityMedium, "error": model.SeverityHigh, "note": model.SeverityLow,
	} {
		if merged[label] != want {
			t.Fatalf("%s: got %v, want %v", label, merged[label], want)
		}
	}
}
