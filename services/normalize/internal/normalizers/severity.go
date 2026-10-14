package normalizers

import (
	"context"
	"maps"
	"strings"

	"vulnmanager/modules/model"
)

const (
	SeverityID NormalizerID = "severity"

	severityVersion NormalizerVersion = "1"
)

const codeUnknownSeverity = "unknown_severity"

type SeverityScale map[model.SeverityRaw]model.Severity

type severity struct {
	scale SeverityScale
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

func NewSeverity(scale SeverityScale) Normalizer {
	return severity{scale: scale}
}

func (severity) ID() NormalizerID {
	return SeverityID
}

func (severity) Version() NormalizerVersion {
	return severityVersion
}

func (severity) Applies(model.Kind) bool {
	return true
}

func (s severity) Normalize(_ context.Context, finding *model.Finding) error {
	label := model.SeverityRaw(strings.ToLower(strings.TrimSpace(string(finding.SeverityRaw))))
	value, known := s.scale[label]
	finding.Severity = value
	if !known && !finding.Diagnostics.Has(codeUnknownSeverity) {
		finding.Diagnostics = finding.Diagnostics.Append(
			model.DiagLevelWarn, codeUnknownSeverity, "severity label "+string(finding.SeverityRaw)+" is not in the scale",
		)
	}
	return nil
}
