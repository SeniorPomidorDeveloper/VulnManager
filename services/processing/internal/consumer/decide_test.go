package consumer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/protobuf/proto"

	commonv1 "vulnmanager/api/gen/go/vulnmanager/common/v1"
	normalizev1 "vulnmanager/api/gen/go/vulnmanager/normalize/v1"
)

type fakeHandler struct {
	err   error
	got   Event
	calls int
}

func (f *fakeHandler) Handle(_ context.Context, event Event) error {
	f.calls++
	f.got = event
	return f.err
}

func body(t *testing.T, tenant, run string) []byte {
	t.Helper()
	encoded, err := proto.Marshal(&normalizev1.ImportCompleted{
		ImportRunId: run,
		Scope:       &commonv1.Scope{TenantId: tenant, ProductId: "product"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestDecideMapsHandlerResultToVerdict(t *testing.T) {
	tests := map[string]struct {
		err  error
		want Verdict
	}{
		"success":         {nil, VerdictAck},
		"transient":       {errors.New("db down"), VerdictRetry},
		"permanent":       {fmt.Errorf("run: %w", ErrPermanent), VerdictDead},
		"wrapped failure": {fmt.Errorf("wrap: %w", errors.New("x")), VerdictRetry},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			handler := &fakeHandler{err: tc.err}

			got := decide(context.Background(), handler, body(t, "tenant", "run-1"), discard())

			if got != tc.want || handler.got != (Event{Tenant: "tenant", Run: "run-1"}) {
				t.Fatalf("verdict=%s event=%+v, want %s", got, handler.got, tc.want)
			}
		})
	}
}

func TestDecidePoisonMessageGoesToDeadLetters(t *testing.T) {
	tests := map[string][]byte{
		"not protobuf":  []byte("\xff\xff\xff"),
		"empty tenant":  body(t, "", "run-1"),
		"empty run id":  body(t, "tenant", ""),
		"empty message": {},
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			handler := &fakeHandler{}

			got := decide(context.Background(), handler, payload, discard())

			if got != VerdictDead || handler.calls != 0 {
				t.Fatalf("verdict=%s calls=%d, want dead and no handling", got, handler.calls)
			}
		})
	}
}
