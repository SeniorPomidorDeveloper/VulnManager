package normalizers

import (
	"context"
	"maps"

	"vulnmanager/modules/model"
)

const (
	SeverityID NormalizerID = "severity"

	severityVersion NormalizerVersion = "2"
)

const codeUnknownSeverity = "unknown_severity"

type SeverityScale map[model.SeverityRaw]model.Severity

type severity struct {
	calculator SeverityCalculator
}

type SeverityCalculator interface {
	Version() NormalizerVersion
	Calculate(finding *model.Finding) (model.Severity, bool)
}

func LabelScale() SeverityScale {
	return SeverityScale{
		"critical":      model.SeverityCritical,
		"high":          model.SeverityHigh,
		"medium":        model.SeverityMedium,
		"moderate":      model.SeverityMedium,
		"low":           model.SeverityLow,
		"info":          model.SeverityInfo,
		"informational": model.SeverityInfo,
		"unknown":       model.SeverityUnknown,
	}
}

func SARIFLevelScale() SeverityScale {
	return SeverityScale{
		"error":   model.SeverityHigh,
		"warning": model.SeverityMedium,
		"note":    model.SeverityLow,
		"none":    model.SeverityInfo,
	}
}

func MergeScales(scales ...SeverityScale) SeverityScale {
	merged := SeverityScale{}
	for _, scale := range scales {
		maps.Copy(merged, scale)
	}
	return merged
}

func NewSeverity(calculator SeverityCalculator) Normalizer {
	return &severity{calculator: calculator}
}

func (*severity) ID() NormalizerID {
	return SeverityID
}

func (n *severity) Version() NormalizerVersion {
	return severityVersion + "(" + n.calculator.Version() + ")"
}

func (*severity) Applies(model.Kind) bool {
	return true
}

func (n *severity) Normalize(_ context.Context, finding *model.Finding) error {
	if value, ok := n.calculator.Calculate(finding); ok {
		finding.Severity = value
		return nil
	}
	finding.Severity = model.SeverityUnknown
	if !finding.Diagnostics.Has(codeUnknownSeverity) {
		finding.Diagnostics = finding.Diagnostics.Append(
			model.DiagLevelWarn, codeUnknownSeverity, "no severity source resolved: label "+string(finding.SeverityRaw),
		)
	}
	return nil
}
