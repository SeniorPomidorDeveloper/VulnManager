package dedup

import (
	"slices"
	"strings"

	"vulnmanager/modules/model"
)

type (
	FeatureID string
	Signal    string
)

const (
	SignalAgree    Signal = "agree"
	SignalDisagree Signal = "disagree"
	SignalUnknown  Signal = "unknown"
)

const (
	FeatureVuln      FeatureID = "vuln"
	FeatureComponent FeatureID = "component"
	FeaturePath      FeatureID = "path"
	FeatureCode      FeatureID = "code"
	FeatureRule      FeatureID = "rule"
	FeatureCWE       FeatureID = "cwe"
	FeatureSeverity  FeatureID = "severity"
	FeatureToolUID   FeatureID = "tool-uid"
)

type Feature interface {
	ID() FeatureID
	Compare(a, b Record) Signal
}

type valuesFeature struct {
	id      FeatureID
	extract func(Record) []string
}

func (f valuesFeature) ID() FeatureID {
	return f.id
}

func (f valuesFeature) Compare(a, b Record) Signal {
	left, right := f.extract(a), f.extract(b)
	if len(left) == 0 || len(right) == 0 {
		return SignalUnknown
	}
	if slices.ContainsFunc(left, func(value string) bool { return slices.Contains(right, value) }) {
		return SignalAgree
	}
	return SignalDisagree
}

func DefaultFeatures() []Feature {
	return []Feature{
		valuesFeature{FeatureVuln, vulnValues},
		valuesFeature{FeatureComponent, componentValues},
		valuesFeature{FeaturePath, func(r Record) []string { return present(r.Path) }},
		valuesFeature{FeatureCode, func(r Record) []string { return present(r.Code) }},
		valuesFeature{FeatureRule, func(r Record) []string { return present(string(r.Rule)) }},
		valuesFeature{FeatureCWE, cweValues},
		valuesFeature{FeatureSeverity, severityValues},
		valuesFeature{FeatureToolUID, func(r Record) []string { return present(r.ToolUID) }},
	}
}

func present(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func vulnValues(r Record) []string {
	if r.Vuln.IsZero() {
		return nil
	}
	return []string{string(r.Vuln.Source) + ":" + r.Vuln.Value}
}

func componentValues(r Record) []string {
	if r.Component.IsZero() {
		return nil
	}
	if r.Component.PURL != "" {
		return []string{string(r.Component.PURL)}
	}
	return []string{strings.Join([]string{
		string(r.Component.Type), r.Component.Namespace, r.Component.Name, r.Component.Version,
	}, "/")}
}

func cweValues(r Record) []string {
	values := make([]string, 0, len(r.CWE))
	for _, name := range r.CWE {
		values = append(values, string(name))
	}
	return values
}

func severityValues(r Record) []string {
	if r.Severity == model.SeverityUnknown {
		return nil
	}
	return []string{r.Severity.String()}
}
