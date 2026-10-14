package blocks

import (
	"cmp"
	"slices"
	"strings"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/cvss"
	"vulnmanager/services/normalize/internal/normalizers"
)

const (
	SeverityFromCVSS  SeveritySource = "cvss"
	SeverityFromScore SeveritySource = "score"
	SeverityFromLabel SeveritySource = "label"
)

const (
	maxScore         = 10
	codeInvalidScore = "invalid_score"
)

type (
	SeveritySource string
	SeverityPolicy []SeveritySource
	CVSSOrder      []model.CVSSSource
)

type priorityCalculator struct {
	scale     SeverityScale
	order     CVSSOrder
	policy    SeverityPolicy
	resolvers map[SeveritySource]func(*model.Finding) (model.Severity, bool)
}

func CVSSSources(sources ...string) CVSSOrder {
	order := make(CVSSOrder, len(sources))
	for i, source := range sources {
		order[i] = model.CVSSSource(source)
	}
	return order
}

func SeverityByPriority(scale SeverityScale, order CVSSOrder, policy ...SeveritySource) normalizers.SeverityCalculator {
	c := &priorityCalculator{scale: scale, order: order, policy: policy}
	c.resolvers = map[SeveritySource]func(*model.Finding) (model.Severity, bool){
		SeverityFromCVSS:  c.fromCVSS,
		SeverityFromScore: c.fromScore,
		SeverityFromLabel: c.fromLabel,
	}
	return c
}

func (c *priorityCalculator) Version() normalizers.NormalizerVersion {
	parts := make([]string, len(c.policy))
	for i, source := range c.policy {
		parts[i] = string(source)
	}
	version := normalizers.NormalizerVersion(strings.Join(parts, ">"))
	if len(c.order) > 0 {
		sources := make([]string, len(c.order))
		for i, source := range c.order {
			sources[i] = string(source)
		}
		version += ";cvss=" + normalizers.NormalizerVersion(strings.Join(sources, ","))
	}
	return version
}

func (c *priorityCalculator) Calculate(finding *model.Finding) (model.Severity, bool) {
	for _, source := range c.policy {
		resolve, known := c.resolvers[source]
		if !known {
			continue
		}
		if value, ok := resolve(finding); ok {
			return value, true
		}
	}
	return model.SeverityUnknown, false
}

func (c *priorityCalculator) fromCVSS(finding *model.Finding) (model.Severity, bool) {
	if len(finding.CVSS) == 0 {
		return model.SeverityUnknown, false
	}
	picked := slices.MinFunc(finding.CVSS, c.compareCVSS)
	return cvss.SeverityFor(cvss.Score(picked.BaseScore), cvss.Version(picked.Version)), true
}

func (*priorityCalculator) fromScore(finding *model.Finding) (model.Severity, bool) {
	if finding.ScannerScore == nil {
		return model.SeverityUnknown, false
	}
	score := *finding.ScannerScore
	if score < 0 || score > maxScore {
		if !finding.Diagnostics.Has(codeInvalidScore) {
			finding.Diagnostics = finding.Diagnostics.Append(model.DiagLevelWarn, codeInvalidScore, "scanner score is outside 0..10")
		}
		return model.SeverityUnknown, false
	}
	return cvss.SeverityFor(cvss.Score(score), cvss.V31), true
}

func (c *priorityCalculator) compareCVSS(a, b model.CVSSScore) int {
	return cmp.Or(
		cmp.Compare(versionRank(a.Version), versionRank(b.Version)),
		cmp.Compare(c.sourceRank(a.Source), c.sourceRank(b.Source)),
		cmp.Compare(a.Source, b.Source),
		cmp.Compare(a.Vector, b.Vector),
	)
}

func (c *priorityCalculator) sourceRank(source model.CVSSSource) int {
	if index := slices.Index(c.order, source); index >= 0 {
		return index
	}
	return len(c.order)
}

var versionRanks = map[model.CVSSVersion]int{
	model.CVSSVersion(cvss.V31): 0,
	model.CVSSVersion(cvss.V30): 0,
	model.CVSSVersion(cvss.V40): 1,
	model.CVSSVersion(cvss.V2):  2,
}

func versionRank(version model.CVSSVersion) int {
	if rank, known := versionRanks[version]; known {
		return rank
	}
	return len(versionRanks)
}

func (c *priorityCalculator) fromLabel(finding *model.Finding) (model.Severity, bool) {
	label := model.SeverityRaw(strings.ToLower(strings.TrimSpace(string(finding.SeverityRaw))))
	value, known := c.scale[label]
	return value, known
}
