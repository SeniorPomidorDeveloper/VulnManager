package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"vulnmanager/services/processing/internal/consumer"
	"vulnmanager/services/processing/internal/store"
	"vulnmanager/services/processing/internal/worker"
)

type recorder interface {
	Record(result worker.Result, took time.Duration, err error)
}

type handler struct {
	worker  *worker.Worker
	metrics recorder
	log     *slog.Logger
}

func (h handler) Handle(ctx context.Context, event consumer.Event) error {
	started := time.Now()
	result, err := h.worker.Handle(ctx, event.Tenant, event.Run)
	h.metrics.Record(result, time.Since(started), err)
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
