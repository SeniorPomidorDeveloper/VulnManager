package consumer

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	ingestv1 "vulnmanager/api/gen/go/vulnmanager/ingest/v1"
	"vulnmanager/services/normalize/internal/worker"
)

type Verdict string

const (
	VerdictAck   Verdict = "ack"
	VerdictRetry Verdict = "retry"
	VerdictDead  Verdict = "dead"
)

var verdicts = map[worker.Action]Verdict{
	worker.ActionAck:   VerdictAck,
	worker.ActionRetry: VerdictRetry,
	worker.ActionDead:  VerdictDead,
}

type Handler interface {
	Handle(ctx context.Context, id uuid.UUID) (worker.Outcome, error)
}

func decide(ctx context.Context, handler Handler, body []byte, log *slog.Logger) Verdict {
	var event ingestv1.ReportReceived
	if err := proto.Unmarshal(body, &event); err != nil {
		log.Warn("undecodable message", "error", err)
		return VerdictDead
	}
	jobID, err := uuid.Parse(event.GetJobId())
	if err != nil {
		log.Warn("message without a valid job id", "job_id", event.GetJobId())
		return VerdictDead
	}
	outcome, err := handler.Handle(ctx, jobID)
	if err != nil {
		log.Warn("job handling failed", "job", jobID, "error", err)
		return VerdictRetry
	}
	if verdict, known := verdicts[outcome.Action]; known {
		return verdict
	}
	return VerdictRetry
}
