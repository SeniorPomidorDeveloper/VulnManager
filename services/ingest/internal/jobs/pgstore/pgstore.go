package pgstore

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vulnmanager/modules/model"
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
	limit, err := db.New(s.pool).GetTenantMaxReportBytes(ctx, string(tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, jobs.ErrTenantNotFound
	}
	return limit, err
}

func (s *Store) FindJob(ctx context.Context, scope model.Scope, tool model.ToolName, sha256 string) (jobs.Job, bool, error) {
	row, err := db.New(s.pool).FindIngestJob(ctx, db.FindIngestJobParams{
		TenantID: string(scope.TenantID),
		ScopeKey: string(scope.Key()),
		Tool:     string(tool),
		Sha256:   sha256,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return jobs.Job{}, false, nil
	}
	if err != nil {
		return jobs.Job{}, false, err
	}
	return jobs.Job{ID: row.ID, ScanID: model.ScanID(row.ScanID), State: jobs.JobState(row.State)}, true, nil
}

func (s *Store) InsertJob(ctx context.Context, scope model.Scope, tool model.ToolName, key model.RawKey) (uuid.UUID, bool, error) {
	id, err := db.New(s.pool).InsertIngestJob(ctx, db.InsertIngestJobParams{
		TenantID:  string(scope.TenantID),
		ScopeKey:  string(scope.Key()),
		ProductID: string(scope.ProductID),
		ContextID: string(scope.ContextID),
		RawKey:    key.String(),
		Tool:      string(tool),
		Sha256:    key.SHA256,
		ScanID:    string(key.ScanID),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	return id, err == nil, err
}
