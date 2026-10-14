package blocks

import "vulnmanager/services/normalize/internal/normalizers"

type Step func() (normalizers.Normalizer, error)

func Compose(steps ...Step) func() (normalizers.Normalizer, error) {
	return func() (normalizers.Normalizer, error) {
		built := make([]normalizers.Normalizer, 0, len(steps))
		for _, step := range steps {
			normalizer, err := step()
			if err != nil {
				return nil, err
			}
			built = append(built, normalizer)
		}
		return normalizers.NewChain(built...)
	}
}

func Severity(calculator normalizers.SeverityCalculator) Step {
	return func() (normalizers.Normalizer, error) { return normalizers.NewSeverity(calculator), nil }
}

func VulnID() (normalizers.Normalizer, error) {
	formats, err := StandardVulnFormats()
	if err != nil {
		return nil, err
	}
	return NewVulnID(formats), nil
}

func Path(fields ...string) Step {
	return func() (normalizers.Normalizer, error) {
		rules, err := StandardPathRules()
		if err != nil {
			return nil, err
		}
		return NewPath(rules, fields...), nil
	}
}
