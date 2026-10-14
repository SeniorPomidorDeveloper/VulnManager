package normalizers_test

import (
	"context"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/normalizers/normtest"
)

type fixedCalculator struct {
	severity model.Severity
	ok       bool
}

func (fixedCalculator) Version() normalizers.NormalizerVersion { return "fixed" }

func (c fixedCalculator) Calculate(*model.Finding) (model.Severity, bool) { return c.severity, c.ok }

func TestSeverity_AppliesTheCalculatorResult(t *testing.T) {
	n := normalizers.NewSeverity(fixedCalculator{severity: model.SeverityHigh, ok: true})
	got := model.Finding{}
	if err := n.Normalize(context.Background(), &got); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got.Severity != model.SeverityHigh || len(got.Diagnostics) != 0 || n.Version() != "2(fixed)" {
		t.Fatalf("severity %v diagnostics %+v version %q", got.Severity, got.Diagnostics, n.Version())
	}
}

func TestSeverity_UnresolvedBecomesUnknownWithOneWarning(t *testing.T) {
	n := normalizers.NewSeverity(fixedCalculator{})
	got := model.Finding{Severity: model.SeverityCritical}
	for range 2 {
		if err := n.Normalize(context.Background(), &got); err != nil {
			t.Fatalf("normalize: %v", err)
		}
	}
	if got.Severity != model.SeverityUnknown || len(got.Diagnostics) != 1 || !got.Diagnostics.Has("unknown_severity") {
		t.Fatalf("severity %v diagnostics %+v", got.Severity, got.Diagnostics)
	}
}

func TestSeverity_Suite(t *testing.T) {
	normtest.Suite(t, normalizers.NewSeverity(fixedCalculator{severity: model.SeverityLow, ok: true}), []model.Finding{{ToolFindingID: "a"}})
}
