package normalizers

func Trivy(order CVSSOrder, policy ...SeveritySource) func() (Normalizer, error) {
	return func() (Normalizer, error) {
		return compose(cvssStep, severityStep(LabelScale(), policy, order), vulnIDStep, componentStep, pathStep("target"))
	}
}
