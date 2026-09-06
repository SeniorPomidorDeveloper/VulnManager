package pipeline

import (
	"context"
	"errors"
	"strconv"
	"testing"
)

func TestChain_Success(t *testing.T) {
	double := StageFunc[int, int](func(_ context.Context, in int) (int, error) {
		return in * 2, nil
	})
	toString := StageFunc[int, string](func(_ context.Context, in int) (string, error) {
		return strconv.Itoa(in), nil
	})
	chained := Chain[int, int, string](double, toString)

	got, err := chained.Run(context.Background(), 21)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "42" {
		t.Fatalf("got %q, want %q", got, "42")
	}
}

func TestChain_ShortCircuitsOnError(t *testing.T) {
	wantErr := errors.New("boom")
	failing := StageFunc[int, int](func(_ context.Context, _ int) (int, error) {
		return 0, wantErr
	})
	called := false
	second := StageFunc[int, int](func(_ context.Context, in int) (int, error) {
		called = true
		return in, nil
	})
	chained := Chain[int, int, int](failing, second)

	_, err := chained.Run(context.Background(), 1)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got err=%v, want %v", err, wantErr)
	}
	if called {
		t.Fatal("second stage was called after first stage failed")
	}
}
