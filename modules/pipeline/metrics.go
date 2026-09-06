package pipeline

import (
	"context"
	"time"
)

func WithMetrics[I, O any](name string, r Recorder) Middleware[I, O] {
	return func(next Stage[I, O]) Stage[I, O] {
		return StageFunc[I, O](func(ctx context.Context, in I) (O, error) {
			start := time.Now()
			out, err := next.Run(ctx, in)
			r.ObserveDuration(name, time.Since(start))
			if err != nil {
				r.IncErrors(name)
			}
			return out, err
		})
	}
}
