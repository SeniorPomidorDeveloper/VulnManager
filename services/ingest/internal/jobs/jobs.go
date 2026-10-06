package jobs

import (
	"context"
	"errors"
	"fmt"

	"vulnmanager/modules/model"
	"vulnmanager/modules/rawstore"
)

var (
	ErrReportTooLarge = errors.New("jobs: report exceeds tenant limit")
	ErrTenantNotFound = errors.New("jobs: tenant not found")
)

type Store interface {
	MaxReportBytes(ctx context.Context, tenantID model.TenantID) (int64, error)
	InsertJob(ctx context.Context, scope model.Scope, rawKey rawstore.Key) error
}

type Enqueuer struct {
	store Store
}

func NewEnqueuer(store Store) *Enqueuer {
	return &Enqueuer{store: store}
}

func (e *Enqueuer) Enqueue(ctx context.Context, scope model.Scope, rawKey rawstore.Key, size int64) error {
	limit, err := e.store.MaxReportBytes(ctx, scope.TenantID)
	if err != nil {
		return fmt.Errorf("tenant limit: %w", err)
	}
	if size > limit {
		return fmt.Errorf("%w: %d > %d", ErrReportTooLarge, size, limit)
	}
	if err := e.store.InsertJob(ctx, scope, rawKey); err != nil {
		return fmt.Errorf("insert job: %w", err)
	}
	return nil
}
