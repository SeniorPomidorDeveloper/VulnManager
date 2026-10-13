package pgstore

import (
	"context"
	"errors"

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

func (s *Store) FindScanID(ctx context.Context, scope model.Scope, tool model.ToolName, sha256 string) (model.ScanID, bool, error) {
	scanID, err := db.New(s.pool).FindIngestJobScanID(ctx, db.FindIngestJobScanIDParams{
		TenantID: string(scope.TenantID),
		ScopeKey: string(scope.Key()),
		Tool:     string(tool),
		Sha256:   sha256,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return model.ScanID(scanID), true, nil
}

func (s *Store) InsertJob(ctx context.Context, scope model.Scope, tool model.ToolName, key model.RawKey) (bool, error) {
	rows, err := db.New(s.pool).InsertIngestJob(ctx, db.InsertIngestJobParams{
		TenantID:  string(scope.TenantID),
		ScopeKey:  string(scope.Key()),
		ProductID: string(scope.ProductID),
		ContextID: string(scope.ContextID),
		RawKey:    key.String(),
		Tool:      string(tool),
		Sha256:    key.SHA256,
		ScanID:    string(key.ScanID),
	})
	return rows > 0, err
}
