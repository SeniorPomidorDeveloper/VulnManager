package pgstore

//go:generate sqlc generate

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vulnmanager/modules/model"
	"vulnmanager/modules/rawstore"
	"vulnmanager/services/ingest/internal/jobs"
	"vulnmanager/services/ingest/internal/jobs/pgstore/gen/jobsdb"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) MaxReportBytes(ctx context.Context, tenantID model.TenantID) (int64, error) {
	var limit int64
	err := s.withTenant(ctx, tenantID, func(q *jobsdb.Queries) error {
		var err error
		limit, err = q.GetTenantMaxReportBytes(ctx, string(tenantID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, jobs.ErrTenantNotFound
	}
	return limit, err
}

func (s *Store) InsertJob(ctx context.Context, scope model.Scope, rawKey rawstore.Key) error {
	return s.withTenant(ctx, scope.TenantID, func(q *jobsdb.Queries) error {
		return q.InsertIngestJob(ctx, jobsdb.InsertIngestJobParams{
			TenantID: string(scope.TenantID),
			ScopeKey: string(scope.Key()),
			RawKey:   rawKey.String(),
		})
	})
}

func (s *Store) withTenant(ctx context.Context, tenantID model.TenantID, fn func(*jobsdb.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	q := jobsdb.New(tx)
	if err := q.SetTenant(ctx, string(tenantID)); err != nil {
		return err
	}
	if err := fn(q); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
