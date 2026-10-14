// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause
// Algorithm: https://github.com/FIRSTdotorg/cvss-v4-calculator (cvss_score.js, max_composed.js, max_severity.js)

package cvss

import (
	"fmt"
	"math"
	"strings"
)

const (
	V40 Version = "4.0"

	unsetMetric  = "X"
	distanceStep = 0.1
)

// Порядок и допустимые значения метрик: FIRST, CVSS v4.0 calculator, cvss_config.js (https://github.com/FIRSTdotorg/cvss-v4-calculator).
var orderV4 = []string{
	"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
	"E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
	"S", "AU", "R", "V", "RE", "U",
}

var (
	requiredV4     = orderV4[:11]
	supplementalV4 = []string{"S", "AU", "R", "V", "RE", "U"}
	urgencyV4      = []string{"X", "CLEAR", "GREEN", "AMBER", "RED"}
)

var valuesV4 = map[string]string{
	"AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA",
	"VC": "HLN", "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "HLN", "SA": "HLN",
	"E": "XAPU", "CR": "XHML", "IR": "XHML", "AR": "XHML",
	"MAV": "XNALP", "MAC": "XLH", "MAT": "XNP", "MPR": "XNLH", "MUI": "XNPA",
	"MVC": "XHLN", "MVI": "XHLN", "MVA": "XHLN", "MSC": "XHLN", "MSI": "XSHLN", "MSA": "XSHLN",
	"S": "XNP", "AU": "XNY", "R": "XAUI", "V": "XDC", "RE": "XLMH",
}

var (
	// Уровни метрик для расстояния до максимального вектора: cvss_score.js (https://github.com/FIRSTdotorg/cvss-v4-calculator), AV_levels ... AR_levels.
	levelsV4 = map[string]map[string]float64{
		"AV": {"N": 0, "A": 0.1, "L": 0.2, "P": 0.3},
		"PR": {"N": 0, "L": 0.1, "H": 0.2},
		"UI": {"N": 0, "P": 0.1, "A": 0.2},
		"AC": {"L": 0, "H": 0.1},
		"AT": {"N": 0, "P": 0.1},
		"VC": {"H": 0, "L": 0.1, "N": 0.2},
		"VI": {"H": 0, "L": 0.1, "N": 0.2},
		"VA": {"H": 0, "L": 0.1, "N": 0.2},
		"SC": {"H": 0.1, "L": 0.2, "N": 0.3},
		"SI": {"S": 0, "H": 0.1, "L": 0.2, "N": 0.3},
		"SA": {"S": 0, "H": 0.1, "L": 0.2, "N": 0.3},
		"CR": {"H": 0, "M": 0.1, "L": 0.2},
		"IR": {"H": 0, "M": 0.1, "L": 0.2},
		"AR": {"H": 0, "M": 0.1, "L": 0.2},
	}
	// Максимальные векторы каждого EQ: max_composed.js (https://github.com/FIRSTdotorg/cvss-v4-calculator).
	eq1Max = map[int][]string{
		0: {"AV:N/PR:N/UI:N/"},
		1: {"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"},
		2: {"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"},
	}
	eq2Max = map[int][]string{
		0: {"AC:L/AT:N/"},
		1: {"AC:H/AT:N/", "AC:L/AT:P/"},
	}
	eq3eq6Max = map[[2]int][]string{
		{0, 0}: {"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"},
		{0, 1}: {"VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"},
		{1, 0}: {"VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"},
		{1, 1}: {
			"VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
			"VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
		},
		{2, 1}: {"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"},
	}
	eq4Max = map[int][]string{0: {"SC:H/SI:S/SA:S/"}, 1: {"SC:H/SI:H/SA:H/"}, 2: {"SC:L/SI:L/SA:L/"}}
	eq5Max = map[int][]string{0: {"E:A/"}, 1: {"E:P/"}, 2: {"E:U/"}}

	// Глубина макровектора (максимальное расстояние, +1): max_severity.js (https://github.com/FIRSTdotorg/cvss-v4-calculator).
	depthEQ1     = map[int]float64{0: 1, 1: 4, 2: 5}
	depthEQ2     = map[int]float64{0: 1, 1: 2}
	depthEQ3EQ6  = map[[2]int]float64{{0, 0}: 7, {0, 1}: 6, {1, 0}: 8, {1, 1}: 8, {2, 1}: 10}
	depthEQ4     = map[int]float64{0: 6, 1: 5, 2: 4}
	distanceKeys = []string{"AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"}
)

type metricsV4 map[string]string

func parseV4(vector, body string) (Result, error) {
	parts := make(metricsV4, len(orderV4))
	for _, pair := range strings.Split(body, "/") {
		key, value, found := strings.Cut(pair, ":")
		key, value = strings.ToUpper(key), strings.ToUpper(value)
		if !found || !validValueV4(key, value) {
			return Result{}, fmt.Errorf("%w: %q: bad metric %q", ErrInvalidVector, vector, pair)
		}
		if _, dup := parts[key]; dup {
			return Result{}, fmt.Errorf("%w: %q: duplicate metric %q", ErrInvalidVector, vector, key)
		}
		parts[key] = value
	}
	for _, key := range requiredV4 {
		if _, ok := parts[key]; !ok {
			return Result{}, fmt.Errorf("%w: %q: missing metric %q", ErrInvalidVector, vector, key)
		}
	}
	return Result{Version: V40, Vector: parts.canonical(), BaseScore: parts.score()}, nil
}

func validValueV4(key, value string) bool {
	if key == "U" {
		return contains(urgencyV4, value)
	}
	allowed, known := valuesV4[key]
	return known && len(value) == 1 && strings.Contains(allowed, value)
}

func (p metricsV4) canonical() string {
	pairs := []string{prefixV3 + string(V40)}
	for _, key := range orderV4 {
		if value, ok := p[key]; ok && value != unsetMetric && !contains(supplementalV4, key) || contains(requiredV4, key) {
			pairs = append(pairs, key+":"+value)
		}
	}
	return strings.Join(pairs, "/")
}

func contains(list []string, item string) bool {
	for _, entry := range list {
		if entry == item {
			return true
		}
	}
	return false
}

func (p metricsV4) metric(name string) string {
	selected := p[name]
	switch {
	case name == "E" && (selected == "" || selected == unsetMetric):
		return "A"
	case (name == "CR" || name == "IR" || name == "AR") && (selected == "" || selected == unsetMetric):
		return "H"
	}
	if modified, ok := p["M"+name]; ok && modified != unsetMetric {
		return modified
	}
	return selected
}

// Уровни EQ1..EQ6: cvss_score.js (https://github.com/FIRSTdotorg/cvss-v4-calculator), функция macroVector.
func (p metricsV4) macroVector() [6]int {
	m := p.metric
	var eq [6]int
	switch {
	case m("AV") == "N" && m("PR") == "N" && m("UI") == "N":
		eq[0] = 0
	case m("AV") == "P" || (m("AV") != "N" && m("PR") != "N" && m("UI") != "N"):
		eq[0] = 2
	default:
		eq[0] = 1
	}
	if m("AC") == "L" && m("AT") == "N" {
		eq[1] = 0
	} else {
		eq[1] = 1
	}
	switch {
	case m("VC") == "H" && m("VI") == "H":
		eq[2] = 0
	case m("VC") == "H" || m("VI") == "H" || m("VA") == "H":
		eq[2] = 1
	default:
		eq[2] = 2
	}
	switch {
	case m("MSI") == "S" || m("MSA") == "S":
		eq[3] = 0
	case m("SC") == "H" || m("SI") == "H" || m("SA") == "H":
		eq[3] = 1
	default:
		eq[3] = 2
	}
	eq[4] = map[string]int{"A": 0, "P": 1, "U": 2}[m("E")]
	if (m("CR") == "H" && m("VC") == "H") || (m("IR") == "H" && m("VI") == "H") || (m("AR") == "H" && m("VA") == "H") {
		eq[5] = 0
	} else {
		eq[5] = 1
	}
	return eq
}

func key(eq [6]int) string {
	return fmt.Sprintf("%d%d%d%d%d%d", eq[0], eq[1], eq[2], eq[3], eq[4], eq[5])
}

func lowerScore(eq [6]int) float64 {
	if score, ok := lookupV4[key(eq)]; ok {
		return score
	}
	return math.NaN()
}

func shifted(eq [6]int, index int) [6]int {
	eq[index]++
	return eq
}

// Оценка: cvss_score.js (https://github.com/FIRSTdotorg/cvss-v4-calculator), функция cvss_score. Оценка макровектора из таблицы
// уменьшается на среднее расстояние от вектора до максимального вектора своего макровектора,
// взвешенное по разнице с ближайшими нижними макровекторами; результат ограничен 0..10 и округлён до десятых.
func (p metricsV4) score() Score {
	allNone := true
	for _, name := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		allNone = allNone && p.metric(name) == "N"
	}
	if allNone {
		return 0
	}
	eq := p.macroVector()
	value := lookupV4[key(eq)]

	next3x6 := lowerScore(shifted(shifted(eq, 2), 5))
	switch {
	case eq[2] == 1 && eq[5] == 1, eq[2] == 0 && eq[5] == 1:
		next3x6 = lowerScore(shifted(eq, 2))
	case eq[2] == 1 && eq[5] == 0:
		next3x6 = lowerScore(shifted(eq, 5))
	case eq[2] == 0 && eq[5] == 0:
		left, right := lowerScore(shifted(eq, 5)), lowerScore(shifted(eq, 2))
		next3x6 = right
		if left > right {
			next3x6 = left
		}
	}
	available := [5]float64{
		value - lowerScore(shifted(eq, 0)),
		value - lowerScore(shifted(eq, 1)),
		value - next3x6,
		value - lowerScore(shifted(eq, 3)),
		value - lowerScore(shifted(eq, 4)),
	}

	distance := p.distanceToMax(eq)
	current := [5]float64{
		distance["AV"] + distance["PR"] + distance["UI"],
		distance["AC"] + distance["AT"],
		distance["VC"] + distance["VI"] + distance["VA"] + distance["CR"] + distance["IR"] + distance["AR"],
		distance["SC"] + distance["SI"] + distance["SA"],
		0,
	}
	depth := [5]float64{
		depthEQ1[eq[0]], depthEQ2[eq[1]], depthEQ3EQ6[[2]int{eq[2], eq[5]}], depthEQ4[eq[3]], 1,
	}

	existing, total := 0, 0.0
	for i := range available {
		if math.IsNaN(available[i]) {
			continue
		}
		existing++
		if i < 4 {
			total += available[i] * (current[i] / (depth[i] * distanceStep))
		}
	}
	if existing > 0 {
		value -= total / float64(existing)
	}
	return Score(math.Round(math.Min(math.Max(value, 0), 10)*10) / 10)
}

func (p metricsV4) distanceToMax(eq [6]int) map[string]float64 {
	var distance map[string]float64
	for _, max := range composeMaxVectors(eq) {
		distance = make(map[string]float64, len(distanceKeys))
		for _, name := range distanceKeys {
			distance[name] = levelsV4[name][p.metric(name)] - levelsV4[name][max[name]]
		}
		if !hasNegative(distance) {
			break
		}
	}
	return distance
}

func hasNegative(distance map[string]float64) bool {
	for _, value := range distance {
		if value < 0 {
			return true
		}
	}
	return false
}

func composeMaxVectors(eq [6]int) []map[string]string {
	var vectors []map[string]string
	for _, a := range eq1Max[eq[0]] {
		for _, b := range eq2Max[eq[1]] {
			for _, c := range eq3eq6Max[[2]int{eq[2], eq[5]}] {
				for _, d := range eq4Max[eq[3]] {
					for _, e := range eq5Max[eq[4]] {
						vectors = append(vectors, parseMax(a+b+c+d+e))
					}
				}
			}
		}
	}
	return vectors
}

func parseMax(vector string) map[string]string {
	parts := map[string]string{}
	for _, pair := range strings.Split(strings.Trim(vector, "/"), "/") {
		key, value, _ := strings.Cut(pair, ":")
		parts[key] = value
	}
	return parts
}
