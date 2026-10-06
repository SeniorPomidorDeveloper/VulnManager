package rawstoreimpl

//go:generate sqlc generate

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vulnmanager/modules/rawstore"
	"vulnmanager/services/ingest/internal/rawstoreimpl/gen/rawblobdb"
)

type PGStore struct {
	pool *pgxpool.Pool
}

func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

func (s *PGStore) Put(ctx context.Context, key rawstore.Key, r io.Reader, _ int64) error {
	content, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return s.withTenant(ctx, string(key.TenantID), func(q *rawblobdb.Queries) error {
		return q.PutRawBlob(ctx, rawblobdb.PutRawBlobParams{
			TenantID:  string(key.TenantID),
			ScanID:    string(key.ScanID),
			Sha256:    key.SHA256,
			Content:   content,
			SizeBytes: int64(len(content)),
		})
	})
}

func (s *PGStore) Get(ctx context.Context, key rawstore.Key) (io.ReadCloser, error) {
	var content []byte
	err := s.withTenant(ctx, string(key.TenantID), func(q *rawblobdb.Queries) error {
		var err error
		content, err = q.GetRawBlobContent(ctx, rawblobdb.GetRawBlobContentParams{
			TenantID: string(key.TenantID),
			ScanID:   string(key.ScanID),
			Sha256:   key.SHA256,
		})
		return err
	})
	if err != nil {
		return nil, translatePGError(err)
	}
	return io.NopCloser(bytes.NewReader(content)), nil
}

func (s *PGStore) Stat(ctx context.Context, key rawstore.Key) (rawstore.Info, error) {
	var size int64
	err := s.withTenant(ctx, string(key.TenantID), func(q *rawblobdb.Queries) error {
		var err error
		size, err = q.GetRawBlobSize(ctx, rawblobdb.GetRawBlobSizeParams{
			TenantID: string(key.TenantID),
			ScanID:   string(key.ScanID),
			Sha256:   key.SHA256,
		})
		return err
	})
	if err != nil {
		return rawstore.Info{}, translatePGError(err)
	}
	return rawstore.Info{Size: size}, nil
}

func (s *PGStore) withTenant(ctx context.Context, tenantID string, fn func(*rawblobdb.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	q := rawblobdb.New(tx)
	if err := q.SetTenant(ctx, tenantID); err != nil {
		return err
	}
	if err := fn(q); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func translatePGError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.Join(rawstore.ErrNotFound, err)
	}
	return err
}
