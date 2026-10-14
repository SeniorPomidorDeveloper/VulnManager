package normalizers

import (
	"context"

	"vulnmanager/modules/model"
)

const (
	SeverityID NormalizerID = "severity"

	severityVersion NormalizerVersion = "2"
)

const codeUnknownSeverity = "unknown_severity"

type severity struct {
	calculator SeverityCalculator
}

type SeverityCalculator interface {
	Version() NormalizerVersion
	Calculate(finding *model.Finding) (model.Severity, bool)
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
