package normalizers

func SARIF(severity SeverityCalculator) func() (Normalizer, error) {
	return func() (Normalizer, error) {
		return compose(severityStep(severity), pathStep("uri"))
	}
}
