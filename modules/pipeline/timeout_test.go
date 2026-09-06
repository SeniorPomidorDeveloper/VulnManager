package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWithTimeout_Exceeded(t *testing.T) {
	slow := StageFunc[int, int](func(ctx context.Context, in int) (int, error) {
		select {
		case <-time.After(50 * time.Millisecond):
			return in, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	wrapped := WithTimeout[int, int](5 * time.Millisecond)(slow)

	_, err := wrapped.Run(context.Background(), 1)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got err=%v, want context.DeadlineExceeded", err)
	}
}

func TestWithTimeout_NotExceeded(t *testing.T) {
	fast := StageFunc[int, int](func(_ context.Context, in int) (int, error) {
		return in * 2, nil
	})
	wrapped := WithTimeout[int, int](50 * time.Millisecond)(fast)

	got, err := wrapped.Run(context.Background(), 21)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 42 {
		t.Fatalf("got %d, want 42", got)
	}
}
