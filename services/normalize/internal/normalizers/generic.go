package normalizers

func NewGeneric() (Normalizer, error) {
	scale := MergeScales(LabelScale(), SARIFLevelScale())
	return compose(severityStep(scale), vulnIDStep, pathStep("uri", "target"))
}
