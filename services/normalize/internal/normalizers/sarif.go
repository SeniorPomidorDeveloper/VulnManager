package normalizers

func SARIF(policy ...SeveritySource) func() (Normalizer, error) {
	return func() (Normalizer, error) {
		return compose(severityStep(SARIFLevelScale(), policy, nil), pathStep("uri"))
	}
}
