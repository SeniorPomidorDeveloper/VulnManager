package normalizers

import (
	"context"
	"fmt"
	"strings"

	"vulnmanager/modules/model"
)

type Chain struct {
	steps []Normalizer
}

type Registry struct {
	byID map[NormalizerID]Normalizer
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

func (c Chain) Apply(ctx context.Context, finding *model.Finding) error {
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

func (c Chain) Version() string {
	parts := make([]string, len(c.steps))
	for i, step := range c.steps {
		parts[i] = fmt.Sprintf("%s@%s", step.ID(), step.Version())
	}
	return strings.Join(parts, "+")
}

func NewRegistry() *Registry {
	return &Registry{byID: make(map[NormalizerID]Normalizer)}
}

func (r *Registry) Register(n Normalizer) error {
	if _, dup := r.byID[n.ID()]; dup {
		return fmt.Errorf("%w: %q", ErrDuplicateNormalizer, n.ID())
	}
	r.byID[n.ID()] = n
	return nil
}

func (r *Registry) Chain(ids ...NormalizerID) (Chain, error) {
	steps := make([]Normalizer, 0, len(ids))
	for _, id := range ids {
		n, ok := r.byID[id]
		if !ok {
			return Chain{}, fmt.Errorf("%w: %q", ErrUnknownNormalizer, id)
		}
		steps = append(steps, n)
	}
	return NewChain(steps...)
}
