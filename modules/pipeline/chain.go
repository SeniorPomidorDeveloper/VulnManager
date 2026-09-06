package pipeline

import "context"

func Chain[I, M, O any](first Stage[I, M], second Stage[M, O]) Stage[I, O] {
	return StageFunc[I, O](func(ctx context.Context, in I) (O, error) {
		mid, err := first.Run(ctx, in)
		if err != nil {
			var zero O
			return zero, err
		}
		return second.Run(ctx, mid)
	})
}
