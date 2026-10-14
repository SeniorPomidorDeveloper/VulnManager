package normalizers

func Generic(severity SeverityCalculator) func() (Normalizer, error) {
	return func() (Normalizer, error) {
		return compose(severityStep(severity), vulnIDStep, pathStep("uri", "target"))
	}
}
