package normalizers

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/cvss"
)

const (
	SeverityID NormalizerID = "severity"

	severityVersion NormalizerVersion = "2"

	FromCVSS  SeveritySource = "cvss"
	FromLabel SeveritySource = "label"
)

const codeUnknownSeverity = "unknown_severity"

type (
	SeverityScale  map[model.SeverityRaw]model.Severity
	SeveritySource string
	SeverityPolicy []SeveritySource
	CVSSOrder      []model.CVSSSource
)

type severity struct {
	scale     SeverityScale
	policy    SeverityPolicy
	order     CVSSOrder
	resolvers map[SeveritySource]func(*model.Finding) (model.Severity, bool)
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

func CVSSFrom(sources ...string) CVSSOrder {
	order := make(CVSSOrder, len(sources))
	for i, source := range sources {
		order[i] = model.CVSSSource(source)
	}
	return order
}

func NewSeverity(scale SeverityScale, policy SeverityPolicy, order CVSSOrder) Normalizer {
	n := &severity{scale: scale, policy: policy, order: order}
	n.resolvers = map[SeveritySource]func(*model.Finding) (model.Severity, bool){
		FromCVSS:  n.fromCVSS,
		FromLabel: n.fromLabel,
	}
	return n
}

func (*severity) ID() NormalizerID {
	return SeverityID
}

func (n *severity) Version() NormalizerVersion {
	parts := make([]string, len(n.policy))
	for i, source := range n.policy {
		parts[i] = string(source)
	}
	version := severityVersion + "(" + NormalizerVersion(strings.Join(parts, ">"))
	if len(n.order) > 0 {
		sources := make([]string, len(n.order))
		for i, source := range n.order {
			sources[i] = string(source)
		}
		version += ";cvss=" + NormalizerVersion(strings.Join(sources, ","))
	}
	return version + ")"
}

func (*severity) Applies(model.Kind) bool {
	return true
}

func (n *severity) Normalize(_ context.Context, finding *model.Finding) error {
	for _, source := range n.policy {
		resolve, known := n.resolvers[source]
		if !known {
			continue
		}
		if value, ok := resolve(finding); ok {
			finding.Severity = value
			return nil
		}
	}
	finding.Severity = model.SeverityUnknown
	if !finding.Diagnostics.Has(codeUnknownSeverity) {
		finding.Diagnostics = finding.Diagnostics.Append(
			model.DiagLevelWarn, codeUnknownSeverity, "no severity source resolved: label "+string(finding.SeverityRaw),
		)
	}
	return nil
}

func (n *severity) fromCVSS(finding *model.Finding) (model.Severity, bool) {
	if len(finding.CVSS) == 0 {
		return model.SeverityUnknown, false
	}
	picked := slices.MinFunc(finding.CVSS, n.compareCVSS)
	return cvss.SeverityFor(cvss.Score(picked.BaseScore), cvss.Version(picked.Version)), true
}

func (n *severity) compareCVSS(a, b model.CVSSScore) int {
	return cmp.Or(
		cmp.Compare(versionRank(a.Version), versionRank(b.Version)),
		cmp.Compare(n.sourceRank(a.Source), n.sourceRank(b.Source)),
		cmp.Compare(a.Source, b.Source),
		cmp.Compare(a.Vector, b.Vector),
	)
}

func (n *severity) sourceRank(source model.CVSSSource) int {
	if index := slices.Index(n.order, source); index >= 0 {
		return index
	}
	return len(n.order)
}

func versionRank(version model.CVSSVersion) int {
	if version == model.CVSSVersion(cvss.V2) {
		return 1
	}
	return 0
}

func (n *severity) fromLabel(finding *model.Finding) (model.Severity, bool) {
	label := model.SeverityRaw(strings.ToLower(strings.TrimSpace(string(finding.SeverityRaw))))
	value, known := n.scale[label]
	return value, known
}
