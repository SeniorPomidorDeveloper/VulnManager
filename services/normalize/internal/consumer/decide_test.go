package consumer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	ingestv1 "vulnmanager/api/gen/go/vulnmanager/ingest/v1"
	"vulnmanager/services/normalize/internal/worker"
)

type fakeHandler struct {
	outcome worker.Outcome
	err     error
	got     uuid.UUID
	calls   int
}

func (f *fakeHandler) Handle(_ context.Context, id uuid.UUID) (worker.Outcome, error) {
	f.calls++
	f.got = id
	return f.outcome, f.err
}

func body(t *testing.T, jobID string) []byte {
	t.Helper()
	encoded, err := proto.Marshal(&ingestv1.ReportReceived{JobId: jobID})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestDecide_MapsOutcomeToVerdict(t *testing.T) {
	tests := map[worker.Action]Verdict{
		worker.ActionAck:   VerdictAck,
		worker.ActionRetry: VerdictRetry,
		worker.ActionDead:  VerdictDead,
		"unknown":          VerdictRetry,
	}
	for action, want := range tests {
		t.Run(string(action), func(t *testing.T) {
			jobID := uuid.New()
			handler := &fakeHandler{outcome: worker.Outcome{Action: action, Delay: time.Minute}}

			got := decide(context.Background(), handler, body(t, jobID.String()), discard())

			if got != want || handler.got != jobID {
				t.Fatalf("verdict=%s handled=%s, want %s for %s", got, handler.got, want, jobID)
			}
		})
	}
}

func TestDecide_HandlerErrorIsRetried(t *testing.T) {
	handler := &fakeHandler{err: errors.New("db down")}

	got := decide(context.Background(), handler, body(t, uuid.NewString()), discard())

	if got != VerdictRetry {
		t.Fatalf("got %s, want retry", got)
	}
}

func TestDecide_PoisonMessageGoesToDeadLetters(t *testing.T) {
	tests := map[string][]byte{
		"not protobuf":    []byte("\xff\xff\xff"),
		"empty job id":    body(t, ""),
		"job id not uuid": body(t, "job-1"),
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
