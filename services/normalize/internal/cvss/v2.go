package cvss

// Значения метрик и формула: FIRST, CVSS v2 Complete Guide, раздел 3.2.1 «Base Equation» (https://www.first.org/cvss/v2/guide)
// (BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))).
var weightsV2 = map[string]map[string]float64{
	"AV": {"L": 0.395, "A": 0.646, "N": 1.0},
	"AC": {"H": 0.35, "M": 0.61, "L": 0.71},
	"AU": {"M": 0.45, "S": 0.56, "N": 0.704},
	"C":  {"N": 0, "P": 0.275, "C": 0.660},
	"I":  {"N": 0, "P": 0.275, "C": 0.660},
	"A":  {"N": 0, "P": 0.275, "C": 0.660},
}

var specV2 = spec{
	order:    []string{"AV", "AC", "AU", "C", "I", "A"},
	weights:  weightsV2,
	ignored:  setOf("E", "RL", "RC", "CDP", "TD", "CR", "IR", "AR"),
	baseCalc: baseV2,
}

// Impact = 10.41*(1-(1-C)(1-I)(1-A)); Exploitability = 20*AV*AC*Au; f(Impact) = 0 при Impact = 0, иначе 1.176.
func baseV2(parts map[string]string, _ Version) Score {
	weights := weightsV2
	impact := 10.41 * (1 - (1-weights["C"][parts["C"]])*(1-weights["I"][parts["I"]])*(1-weights["A"][parts["A"]]))
	exploitability := 20 * weights["AV"][parts["AV"]] * weights["AC"][parts["AC"]] * weights["AU"][parts["AU"]]
	factor := 1.176
	if impact == 0 {
		factor = 0
	}
	return roundTenth((0.6*impact + 0.4*exploitability - 1.5) * factor)
}
