package consumer

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/protobuf/proto"

	normalizev1 "vulnmanager/api/gen/go/vulnmanager/normalize/v1"
	"vulnmanager/modules/model"
)

type Verdict string

const (
	VerdictAck   Verdict = "ack"
	VerdictRetry Verdict = "retry"
	VerdictDead  Verdict = "dead"
)

var ErrPermanent = errors.New("consumer: permanent failure")

type Event struct {
	Tenant model.TenantID
	Run    model.ImportRunID
}

type Handler interface {
	Handle(ctx context.Context, event Event) error
}

func decide(ctx context.Context, handler Handler, body []byte, log *slog.Logger) Verdict {
	var message normalizev1.ImportCompleted
	if err := proto.Unmarshal(body, &message); err != nil {
		log.Warn("undecodable message", "error", err)
		return VerdictDead
	}
	event := Event{
		Tenant: model.TenantID(message.GetScope().GetTenantId()),
		Run:    model.ImportRunID(message.GetImportRunId()),
	}
	if event.Tenant.IsEmpty() || event.Run == "" {
		log.Warn("message without tenant or import run id")
		return VerdictDead
	}
	err := handler.Handle(ctx, event)
	if errors.Is(err, ErrPermanent) {
		log.Warn("import run handling failed permanently", "run", event.Run, "error", err)
		return VerdictDead
	}
	if err != nil {
		log.Warn("import run handling failed", "run", event.Run, "error", err)
		return VerdictRetry
	}
	return VerdictAck
}
