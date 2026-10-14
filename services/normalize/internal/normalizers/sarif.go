package normalizers

func NewSARIF() (Normalizer, error) {
	return compose(severityStep(SARIFLevelScale()), pathStep("uri"))
}
