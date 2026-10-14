package normalizers

import (
	"context"
	"fmt"
	"strings"

	"vulnmanager/modules/model"
)

const ChainID NormalizerID = "chain"

type Chain struct {
	steps []Normalizer
}

func NewChain(steps ...Normalizer) (Chain, error) {
	seen := make(map[NormalizerID]struct{}, len(steps))
	for _, step := range steps {
		if _, dup := seen[step.ID()]; dup {
			return Chain{}, fmt.Errorf("%w: %q", ErrDuplicateNormalizer, step.ID())
		}
		seen[step.ID()] = struct{}{}
	}
	return Chain{steps: append([]Normalizer(nil), steps...)}, nil
}

func (Chain) ID() NormalizerID {
	return ChainID
}

func (Chain) Applies(model.Kind) bool {
	return true
}

func (c Chain) Normalize(ctx context.Context, finding *model.Finding) error {
	for _, step := range c.steps {
		if !step.Applies(finding.Kind) {
			continue
		}
		if err := step.Normalize(ctx, finding); err != nil {
			return fmt.Errorf("normalizer %s: %w", step.ID(), err)
		}
	}
	return nil
}

func (c Chain) Version() NormalizerVersion {
	parts := make([]string, len(c.steps))
	for i, step := range c.steps {
		parts[i] = fmt.Sprintf("%s@%s", step.ID(), step.Version())
	}
	return NormalizerVersion(strings.Join(parts, "+"))
}
