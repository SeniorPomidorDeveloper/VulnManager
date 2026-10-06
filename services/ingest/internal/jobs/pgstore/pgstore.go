package pgstore

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vulnmanager/modules/model"
	"vulnmanager/modules/rawstore"
	"vulnmanager/services/ingest/gen/db"
	"vulnmanager/services/ingest/internal/jobs"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) MaxReportBytes(ctx context.Context, tenantID model.TenantID) (int64, error) {
	var limit int64
	err := s.withTenant(ctx, tenantID, func(q *db.Queries) error {
		var err error
		limit, err = q.GetTenantMaxReportBytes(ctx, string(tenantID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, jobs.ErrTenantNotFound
	}
	return limit, err
}

func (s *Store) FindScanID(ctx context.Context, scope model.Scope, tool, sha256 string) (model.ScanID, bool, error) {
	var scanID string
	err := s.withTenant(ctx, scope.TenantID, func(q *db.Queries) error {
		var err error
		scanID, err = q.FindIngestJobScanID(ctx, db.FindIngestJobScanIDParams{
			TenantID: string(scope.TenantID),
			ScopeKey: string(scope.Key()),
			Tool:     tool,
			Sha256:   sha256,
		})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return model.ScanID(scanID), true, nil
}

func (s *Store) InsertJob(ctx context.Context, scope model.Scope, tool string, key rawstore.Key) (bool, error) {
	var rows int64
	err := s.withTenant(ctx, scope.TenantID, func(q *db.Queries) error {
		var err error
		rows, err = q.InsertIngestJob(ctx, db.InsertIngestJobParams{
			TenantID: string(scope.TenantID),
			ScopeKey: string(scope.Key()),
			RawKey:   key.String(),
			Tool:     tool,
			Sha256:   key.SHA256,
			ScanID:   string(key.ScanID),
		})
		return err
	})
	return rows > 0, err
}

func (s *Store) withTenant(ctx context.Context, tenantID model.TenantID, fn func(*db.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	q := db.New(tx)
	if err := q.SetTenant(ctx, string(tenantID)); err != nil {
		return err
	}
	if err := fn(q); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
