package pipeline

import (
	"context"
	"reflect"
	"testing"
)

func TestWrap_Order(t *testing.T) {
	var order []string
	track := func(name string) Middleware[int, int] {
		return func(next Stage[int, int]) Stage[int, int] {
			return StageFunc[int, int](func(ctx context.Context, in int) (int, error) {
				order = append(order, name+":before")
				out, err := next.Run(ctx, in)
				order = append(order, name+":after")
				return out, err
			})
		}
	}
	base := StageFunc[int, int](func(_ context.Context, in int) (int, error) { return in, nil })
	wrapped := Wrap(base, track("outer"), track("inner"))

	if _, err := wrapped.Run(context.Background(), 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"outer:before", "inner:before", "inner:after", "outer:after"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("got %v, want %v", order, want)
	}
}

func TestWrap_NoMiddlewares(t *testing.T) {
	base := StageFunc[int, int](func(_ context.Context, in int) (int, error) { return in * 2, nil })
	wrapped := Wrap[int, int](base)

	got, err := wrapped.Run(context.Background(), 21)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 42 {
		t.Fatalf("got %d, want 42", got)
	}
}
