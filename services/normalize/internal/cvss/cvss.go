package cvss

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"vulnmanager/modules/model"
)

const (
	V2  Version = "2.0"
	V30 Version = "3.0"
	V31 Version = "3.1"

	prefixV3 = "CVSS:"
)

var ErrInvalidVector = errors.New("cvss: invalid vector")

type (
	Version string
	Score   float64
)

type Result struct {
	Version   Version
	Vector    string
	BaseScore Score
}

type band struct {
	min      Score
	severity model.Severity
}

type spec struct {
	order    []string
	weights  map[string]map[string]float64
	ignored  map[string]bool
	baseCalc func(parts map[string]string, version Version) Score
}

var keyDisplay = map[string]string{"AU": "Au"}

// bandsV3: FIRST, CVSS v3.1 Specification Document, раздел 5, таблица 14 «Qualitative severity rating scale»
// (https://www.first.org/cvss/v3.1/specification-document): None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0.
// bandsV2: у CVSS v2 в руководстве FIRST текстовой шкалы нет; границы Low/Medium/High (0-3.9/4-6.9/7-10)
// взяты из шкалы NVD для v2 (https://nvd.nist.gov/vuln-metrics/cvss) и по первоисточнику не сверены.
var (
	bandsV3 = []band{
		{9.0, model.SeverityCritical},
		{7.0, model.SeverityHigh},
		{4.0, model.SeverityMedium},
		{0.1, model.SeverityLow},
		{0, model.SeverityInfo},
	}
	bandsV2 = []band{
		{7.0, model.SeverityHigh}, {4.0, model.SeverityMedium}, {0.1, model.SeverityLow}, {0, model.SeverityInfo},
	}
)

func Parse(vector string) (Result, error) {
	vector = strings.TrimSpace(vector)
	version, body := V2, vector
	if strings.HasPrefix(strings.ToUpper(vector), prefixV3) {
		head, rest, found := strings.Cut(vector, "/")
		if !found {
			return Result{}, fmt.Errorf("%w: %q has no metrics", ErrInvalidVector, vector)
		}
		version, body = Version(head[len(prefixV3):]), rest
	}
	if version == V40 {
		return parseV4(vector, body)
	}
	vectorSpec, known := specs[version]
	if !known {
		return Result{}, fmt.Errorf("%w: unsupported version in %q", ErrInvalidVector, vector)
	}
	parts, err := vectorSpec.parse(body)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %q: %w", ErrInvalidVector, vector, err)
	}
	return Result{Version: version, Vector: vectorSpec.canonical(version, parts), BaseScore: vectorSpec.baseCalc(parts, version)}, nil
}

func (r Result) Severity() model.Severity {
	return SeverityFor(r.BaseScore, r.Version)
}

func SeverityFor(score Score, version Version) model.Severity {
	bands := bandsV3
	if version == V2 {
		bands = bandsV2
	}
	for _, b := range bands {
		if score >= b.min {
			return b.severity
		}
	}
	return model.SeverityInfo
}

func (s spec) parse(body string) (map[string]string, error) {
	parts := make(map[string]string, len(s.order))
	for _, pair := range strings.Split(strings.Trim(body, "()"), "/") {
		key, value, found := strings.Cut(pair, ":")
		if !found {
			return nil, fmt.Errorf("bad metric %q", pair)
		}
		key, value = strings.ToUpper(key), strings.ToUpper(value)
		if s.ignored[key] {
			continue
		}
		allowed, known := s.weights[key]
		if _, ok := allowed[value]; !known || !ok {
			return nil, fmt.Errorf("bad metric %q", pair)
		}
		if _, dup := parts[key]; dup {
			return nil, fmt.Errorf("duplicate metric %q", key)
		}
		parts[key] = value
	}
	for _, key := range s.order {
		if _, ok := parts[key]; !ok {
			return nil, fmt.Errorf("missing metric %q", key)
		}
	}
	return parts, nil
}

func (s spec) canonical(version Version, parts map[string]string) string {
	pairs := make([]string, len(s.order))
	for i, key := range s.order {
		pairs[i] = displayName(key) + ":" + parts[key]
	}
	joined := strings.Join(pairs, "/")
	if version == V2 {
		return joined
	}
	return prefixV3 + string(version) + "/" + joined
}

func displayName(key string) string {
	if name, ok := keyDisplay[key]; ok {
		return name
	}
	return key
}

func roundTenth(value float64) Score {
	return Score(math.Round(value*10+1e-9) / 10)
}
