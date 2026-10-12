package rawstoreimpl

import (
	"context"
	"io"

	"github.com/jackc/pgx/v5/pgxpool"

	"vulnmanager/modules/model"
	"vulnmanager/services/ingest/gen/db"
)

type PGWriter struct {
	pool *pgxpool.Pool
}

func NewPGWriter(pool *pgxpool.Pool) *PGWriter {
	return &PGWriter{pool: pool}
}

func (s *PGWriter) Put(ctx context.Context, key model.RawKey, r io.Reader, _ int64) error {
	content, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return s.withTenant(ctx, string(key.TenantID), func(q *db.Queries) error {
		return q.PutRawBlob(ctx, db.PutRawBlobParams{
			TenantID:  string(key.TenantID),
			ScanID:    string(key.ScanID),
			Sha256:    key.SHA256,
			Content:   content,
			SizeBytes: int64(len(content)),
		})
	})
}

func (s *PGWriter) withTenant(ctx context.Context, tenantID string, fn func(*db.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	q := db.New(tx)
	if err := q.SetTenant(ctx, tenantID); err != nil {
		return err
	}
	if err := fn(q); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
