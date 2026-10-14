package normalizers

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"vulnmanager/modules/model"
)

const (
	VulnIDNormalizer NormalizerID = "vulnid"

	vulnIDVersion NormalizerVersion = "1"

	CaseUpper CaseRule = "upper"
	CaseLower CaseRule = "lower"
	CaseKeep  CaseRule = "keep"
)

const codeUnknownVulnID = "unknown_vuln_id_format"

var ErrInvalidVulnFormat = errors.New("normalizers: invalid vulnerability id format")

var caseRules = map[CaseRule]func(string) string{
	CaseUpper: strings.ToUpper,
	CaseLower: strings.ToLower,
	CaseKeep:  func(body string) string { return body },
}

type CaseRule string

type VulnFormat struct {
	source model.VulnSource
	prefix string
	body   *regexp.Regexp
	rule   func(string) string
}

type vulnID struct {
	formats []VulnFormat
}

func NewVulnFormat(source model.VulnSource, prefix, body string, rule CaseRule) (VulnFormat, error) {
	apply, known := caseRules[rule]
	if source == "" || prefix == "" || !known {
		return VulnFormat{}, fmt.Errorf("%w: source=%q prefix=%q case=%q", ErrInvalidVulnFormat, source, prefix, rule)
	}
	pattern, err := regexp.Compile("(?i)^(?:" + body + ")$")
	if err != nil {
		return VulnFormat{}, fmt.Errorf("%w: body %q: %w", ErrInvalidVulnFormat, body, err)
	}
	return VulnFormat{source: source, prefix: strings.ToUpper(prefix), body: pattern, rule: apply}, nil
}

func (f VulnFormat) canonical(raw string) (model.VulnID, bool) {
	if len(raw) <= len(f.prefix) || !strings.EqualFold(raw[:len(f.prefix)], f.prefix) {
		return model.VulnID{}, false
	}
	body := raw[len(f.prefix):]
	if !f.body.MatchString(body) {
		return model.VulnID{}, false
	}
	return model.VulnID{Source: f.source, Value: f.prefix + f.rule(body)}, true
}

func NewVulnID(formats []VulnFormat) Normalizer {
	return vulnID{formats: formats}
}

func (vulnID) ID() NormalizerID {
	return VulnIDNormalizer
}

func (vulnID) Version() NormalizerVersion {
	return vulnIDVersion
}

func (vulnID) Applies(model.Kind) bool {
	return true
}

func (n vulnID) Normalize(_ context.Context, finding *model.Finding) error {
	raw := strings.TrimSpace(string(finding.VulnIDRaw))
	finding.VulnID = model.VulnID{}
	if raw == "" {
		return nil
	}
	for _, format := range n.formats {
		if id, ok := format.canonical(raw); ok {
			finding.VulnID = id
			return nil
		}
	}
	finding.VulnID = model.VulnID{Source: model.VulnSourceUnknown, Value: raw}
	if !finding.Diagnostics.Has(codeUnknownVulnID) {
		finding.Diagnostics = finding.Diagnostics.Append(
			model.DiagLevelWarn, codeUnknownVulnID, "vulnerability id "+raw+" matches no known format",
		)
	}
	return nil
}
