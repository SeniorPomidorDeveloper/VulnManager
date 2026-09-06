package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeRecorder struct {
	durations map[string]time.Duration
	errors    map[string]int
}

func newFakeRecorder() *fakeRecorder {
	return &fakeRecorder{durations: map[string]time.Duration{}, errors: map[string]int{}}
}

func (f *fakeRecorder) ObserveDuration(stage string, d time.Duration) {
	f.durations[stage] = d
}

func (f *fakeRecorder) IncErrors(stage string) {
	f.errors[stage]++
}

func TestWithMetrics_Success(t *testing.T) {
	rec := newFakeRecorder()
	ok := StageFunc[int, int](func(_ context.Context, in int) (int, error) { return in, nil })
	wrapped := WithMetrics[int, int]("dedup", rec)(ok)

	if _, err := wrapped.Run(context.Background(), 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := rec.durations["dedup"]; !ok {
		t.Fatal("duration was not recorded")
	}
	if rec.errors["dedup"] != 0 {
		t.Fatalf("got %d errors, want 0", rec.errors["dedup"])
	}
}

func TestWithMetrics_Error(t *testing.T) {
	rec := newFakeRecorder()
	wantErr := errors.New("boom")
	failing := StageFunc[int, int](func(_ context.Context, _ int) (int, error) { return 0, wantErr })
	wrapped := WithMetrics[int, int]("dedup", rec)(failing)

	_, err := wrapped.Run(context.Background(), 1)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got err=%v, want %v", err, wantErr)
	}
	if rec.errors["dedup"] != 1 {
		t.Fatalf("got %d errors, want 1", rec.errors["dedup"])
	}
}
