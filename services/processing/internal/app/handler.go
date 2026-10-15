package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"vulnmanager/services/processing/internal/consumer"
	"vulnmanager/services/processing/internal/store"
	"vulnmanager/services/processing/internal/worker"
)

type handler struct {
	worker *worker.Worker
	log    *slog.Logger
}

func (h handler) Handle(ctx context.Context, event consumer.Event) error {
	result, err := h.worker.Handle(ctx, event.Tenant, event.Run)
	if errors.Is(err, store.ErrRunNotFound) || errors.Is(err, store.ErrRunNotCompleted) {
		return fmt.Errorf("%w: %w", consumer.ErrPermanent, err)
	}
	if err != nil {
		return err
	}
	h.log.Info("import run processed",
		"run", event.Run, "tool", result.Tool, "already", result.Already,
		"findings", result.Findings, "unfingerprinted", result.Unfingerprinted,
	)
	return nil
}
