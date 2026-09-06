package pipeline

import "context"

func WithTracing[I, O any](name string, t SpanStarter) Middleware[I, O] {
	return func(next Stage[I, O]) Stage[I, O] {
		return StageFunc[I, O](func(ctx context.Context, in I) (O, error) {
			ctx, end := t.StartSpan(ctx, name)
			defer end()
			return next.Run(ctx, in)
		})
	}
}
