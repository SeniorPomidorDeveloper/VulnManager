package normalizers

import (
	"context"
	"strings"

	"vulnmanager/modules/model"
)

const (
	SeverityID NormalizerID = "severity"

	severityVersion NormalizerVersion = "1"
)

const codeUnknownSeverity = "unknown_severity"

type SeverityScale map[model.SeverityRaw]model.Severity

type SeverityScales struct {
	ByTool  map[model.ToolName]SeverityScale
	Default SeverityScale
}

type severity struct {
	scales SeverityScales
}

func NewSeverity(scales SeverityScales) Normalizer {
	return severity{scales: scales}
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
	scale, ok := s.scales.ByTool[finding.Provenance.Tool]
	if !ok {
		scale = s.scales.Default
	}
	value, known := scale[label]
	finding.Severity = value
	if !known && !finding.Diagnostics.Has(codeUnknownSeverity) {
		finding.Diagnostics = finding.Diagnostics.Append(
			model.DiagLevelWarn, codeUnknownSeverity, "severity label "+string(finding.SeverityRaw)+" is not in the scale",
		)
	}
	return nil
}
