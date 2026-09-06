package pipeline

import (
	"context"
	"testing"
)

type fakeTracer struct {
	started []string
	ended   int
}

func (f *fakeTracer) StartSpan(ctx context.Context, name string) (context.Context, func()) {
	f.started = append(f.started, name)
	return ctx, func() { f.ended++ }
}

func TestWithTracing(t *testing.T) {
	tr := &fakeTracer{}
	ok := StageFunc[int, int](func(_ context.Context, in int) (int, error) { return in, nil })
	wrapped := WithTracing[int, int]("dedup", tr)(ok)

	if _, err := wrapped.Run(context.Background(), 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tr.started) != 1 || tr.started[0] != "dedup" {
		t.Fatalf("got started=%v, want [dedup]", tr.started)
	}
	if tr.ended != 1 {
		t.Fatalf("got ended=%d, want 1", tr.ended)
	}
}
