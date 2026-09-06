//go:build integration

package rawstore_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"vulnmanager/modules/rawstore"
	"vulnmanager/modules/rawstore/rawstoretest"
)

func TestPGStore_ContractSuite(t *testing.T) {
	dsn := os.Getenv("RAWSTORE_TEST_PG_DSN")
	if dsn == "" {
		dsn = "postgres://vulnmanager:vulnmanager-local-dev@localhost:5432/vulnmanager"
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	applyMigration(t, pool)

	rawstoretest.RunContractSuite(t, func() rawstore.Store {
		return rawstore.NewPGStore(pool)
	})
}

func applyMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS raw_blob CASCADE`); err != nil {
		t.Fatalf("drop raw_blob: %v", err)
	}

	migration, err := os.ReadFile("../../migrations/ingest/V0001__raw_blob.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
}
