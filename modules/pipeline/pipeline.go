package pipeline

import "context"

type Stage[I, O any] interface {
	Run(ctx context.Context, in I) (O, error)
}

type StageFunc[I, O any] func(ctx context.Context, in I) (O, error)

func (f StageFunc[I, O]) Run(ctx context.Context, in I) (O, error) {
	return f(ctx, in)
}
