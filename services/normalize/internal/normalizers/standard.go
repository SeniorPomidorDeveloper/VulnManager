package normalizers

type stepFactory func() (Normalizer, error)

func severityStep(calculator SeverityCalculator) stepFactory {
	return func() (Normalizer, error) { return NewSeverity(calculator), nil }
}

func vulnIDStep() (Normalizer, error) {
	formats, err := StandardVulnFormats()
	if err != nil {
		return nil, err
	}
	return NewVulnID(formats), nil
}

func pathStep(fields ...string) stepFactory {
	return func() (Normalizer, error) {
		rules, err := StandardPathRules()
		if err != nil {
			return nil, err
		}
		return NewPath(rules, fields...), nil
	}
}

func compose(factories ...stepFactory) (Normalizer, error) {
	steps := make([]Normalizer, 0, len(factories))
	for _, factory := range factories {
		step, err := factory()
		if err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}
	return NewChain(steps...)
}
