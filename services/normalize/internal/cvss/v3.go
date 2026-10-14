package cvss

import "math"

const (
	scopeChanged   = "C"
	roundupScale   = 100000
	roundupDivisor = 10000
)

var specs = map[Version]spec{V2: specV2, V30: specV3, V31: specV3}

// Числовые значения метрик: FIRST, CVSS v3.1 Specification Document (https://www.first.org/cvss/v3.1/specification-document),
// раздел 7.4 «Metric Values», таблица 16 (для 3.0 значения те же).
// Для PR второе значение при изменённом Scope лежит в privilegesChanged.
var weightsV3 = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"PR": {"N": 0.85, "L": 0.62, "H": 0.27},
	"UI": {"N": 0.85, "R": 0.62},
	"S":  {"U": 0, "C": 0},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

var specV3 = spec{
	order:    []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"},
	weights:  weightsV3,
	ignored:  setOf("E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"),
	baseCalc: baseV3,
}

// Таблица 16: Privileges Required Low 0.62 (0.68 при Scope Changed), High 0.27 (0.5 при Scope Changed).
var privilegesChanged = map[string]float64{"L": 0.68, "H": 0.5}

// Базовая оценка: CVSS v3.1 Specification Document, раздел 7.1 «Base Metrics Equations» (https://www.first.org/cvss/v3.1/specification-document).
// ISS = 1 - (1-C)(1-I)(1-A); Exploitability = 8.22*AV*AC*PR*UI;
// Impact = 6.42*ISS при Scope Unchanged, 7.52*(ISS-0.029) - 3.25*(ISS-0.02)^15 при Changed;
// BaseScore = 0 при Impact <= 0, иначе Roundup(min(Impact+Exploitability, 10)),
// а при Scope Changed Roundup(min(1.08*(Impact+Exploitability), 10)).
func baseV3(parts map[string]string, version Version) Score {
	weights := weightsV3
	changed := parts["S"] == scopeChanged
	privileges := weights["PR"][parts["PR"]]
	if override, ok := privilegesChanged[parts["PR"]]; ok && changed {
		privileges = override
	}
	exploitability := 8.22 * weights["AV"][parts["AV"]] * weights["AC"][parts["AC"]] * privileges * weights["UI"][parts["UI"]]
	iss := 1 - (1-weights["C"][parts["C"]])*(1-weights["I"][parts["I"]])*(1-weights["A"][parts["A"]])
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0
	}
	total := impact + exploitability
	if changed {
		total *= 1.08
	}
	return roundup(math.Min(total, 10), version)
}

// Roundup: v3.1 — функция из приложения A спецификации (https://www.first.org/cvss/v3.1/specification-document; целочисленная арифметика,
// без ошибок плавающей точки); v3.0 — округление вверх до десятых, как в спецификации 3.0.
func roundup(value float64, version Version) Score {
	if version == V30 {
		return Score(math.Ceil(value*10) / 10)
	}
	scaled := int(math.Round(value * roundupScale))
	if scaled%roundupDivisor == 0 {
		return Score(float64(scaled) / roundupScale)
	}
	return Score(float64(scaled/roundupDivisor+1) / 10)
}

func setOf(keys ...string) map[string]bool {
	set := make(map[string]bool, len(keys))
	for _, key := range keys {
		set[key] = true
	}
	return set
}
