package normalizers

func Trivy(severity SeverityCalculator) func() (Normalizer, error) {
	return func() (Normalizer, error) {
		return compose(cvssStep, severityStep(severity), vulnIDStep, componentStep, pathStep("target"))
	}
}
