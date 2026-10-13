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
	return db.New(s.pool).PutRawBlob(ctx, db.PutRawBlobParams{
		TenantID:  string(key.TenantID),
		ScanID:    string(key.ScanID),
		Sha256:    key.SHA256,
		Content:   content,
		SizeBytes: int64(len(content)),
	})
}
