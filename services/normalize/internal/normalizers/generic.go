package normalizers

func Generic(policy ...SeveritySource) func() (Normalizer, error) {
	return func() (Normalizer, error) {
		scale := MergeScales(LabelScale(), SARIFLevelScale())
		return compose(severityStep(scale, policy, nil), vulnIDStep, pathStep("uri", "target"))
	}
}
