package pipeline

import (
	"context"
	"time"
)

func WithTimeout[I, O any](d time.Duration) Middleware[I, O] {
	return func(next Stage[I, O]) Stage[I, O] {
		return StageFunc[I, O](func(ctx context.Context, in I) (O, error) {
			ctx, cancel := context.WithTimeout(ctx, d)
			defer cancel()
			return next.Run(ctx, in)
		})
	}
}
