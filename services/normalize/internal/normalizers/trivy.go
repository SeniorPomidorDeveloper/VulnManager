package normalizers

func NewTrivy() (Normalizer, error) {
	return compose(severityStep(LabelScale()), vulnIDStep, pathStep("target"))
}
