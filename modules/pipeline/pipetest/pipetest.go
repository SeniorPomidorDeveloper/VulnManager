package pipetest

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"vulnmanager/modules/pipeline"
)

func RunContractSuite[I, O any](t *testing.T, newStage func() pipeline.Stage[I, O], in I, want O) {
	t.Helper()

	t.Run("returns expected output", func(t *testing.T) {
		s := newStage()
		got, err := s.Run(context.Background(), in)
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("no-op middleware preserves output", func(t *testing.T) {
		noop := pipeline.Middleware[I, O](func(next pipeline.Stage[I, O]) pipeline.Stage[I, O] {
			return next
		})
		s := pipeline.Wrap(newStage(), noop)
		got, err := s.Run(context.Background(), in)
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("cancelled context is either respected or ignored, never misreported", func(t *testing.T) {
		s := newStage()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := s.Run(ctx, in); err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("got err=%v, want nil or a context.Canceled-wrapped error", err)
		}
	})
}
