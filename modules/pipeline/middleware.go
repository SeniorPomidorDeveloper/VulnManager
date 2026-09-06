package pipeline

type Middleware[I, O any] func(Stage[I, O]) Stage[I, O]

func Wrap[I, O any](s Stage[I, O], mws ...Middleware[I, O]) Stage[I, O] {
	for i := len(mws) - 1; i >= 0; i-- {
		s = mws[i](s)
	}
	return s
}
