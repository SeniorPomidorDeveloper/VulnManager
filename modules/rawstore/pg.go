package rawstore

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PGStore struct {
	pool *pgxpool.Pool
}

func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

func (s *PGStore) Put(ctx context.Context, key Key, r io.Reader, _ int64) error {
	content, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return s.withTenant(ctx, key.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO raw_blob (tenant_id, scan_id, sha256, content, size_bytes)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, scan_id, sha256) DO NOTHING
		`, key.TenantID, key.ScanID, key.SHA256, content, len(content))
		return err
	})
}

func (s *PGStore) Get(ctx context.Context, key Key) (io.ReadCloser, error) {
	var content []byte
	err := s.withTenant(ctx, key.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT content FROM raw_blob WHERE tenant_id = $1 AND scan_id = $2 AND sha256 = $3
		`, key.TenantID, key.ScanID, key.SHA256).Scan(&content)
	})
	if err != nil {
		return nil, translatePGError(err)
	}
	return io.NopCloser(bytes.NewReader(content)), nil
}

func (s *PGStore) Stat(ctx context.Context, key Key) (Info, error) {
	var size int64
	err := s.withTenant(ctx, key.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT size_bytes FROM raw_blob WHERE tenant_id = $1 AND scan_id = $2 AND sha256 = $3
		`, key.TenantID, key.ScanID, key.SHA256).Scan(&size)
	})
	if err != nil {
		return Info{}, translatePGError(err)
	}
	return Info{Size: size}, nil
}

// withTenant runs fn in a transaction with the RLS session GUC app.tenant_id set for
// that transaction only, so isolation holds regardless of which role owns the table.
func (s *PGStore) withTenant(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // best-effort rollback after commit or error

	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func translatePGError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.Join(ErrNotFound, err)
	}
	return err
}
