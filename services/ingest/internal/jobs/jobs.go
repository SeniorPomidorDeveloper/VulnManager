package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"vulnmanager/modules/model"
	"vulnmanager/modules/rawstore"
)

var (
	ErrReportTooLarge = errors.New("jobs: report exceeds tenant limit")
	ErrTenantNotFound = errors.New("jobs: tenant not found")
)

type Report struct {
	Scope  model.Scope
	Tool   string
	ScanID model.ScanID
	Body   []byte
}

type Accepted struct {
	ScanID model.ScanID
	SHA256 string
}

type Store interface {
	MaxReportBytes(ctx context.Context, tenantID model.TenantID) (int64, error)
	FindScanID(ctx context.Context, scope model.Scope, tool, sha256 string) (model.ScanID, bool, error)
	InsertJob(ctx context.Context, scope model.Scope, tool string, key rawstore.Key) (bool, error)
}

type Enqueuer struct {
	store Store
	raw   rawstore.Store
}

func NewEnqueuer(store Store, raw rawstore.Store) *Enqueuer {
	return &Enqueuer{store: store, raw: raw}
}

func (e *Enqueuer) MaxReportBytes(ctx context.Context, tenantID model.TenantID) (int64, error) {
	return e.store.MaxReportBytes(ctx, tenantID)
}

func (e *Enqueuer) Accept(ctx context.Context, r Report) (Accepted, error) {
	limit, err := e.store.MaxReportBytes(ctx, r.Scope.TenantID)
	if err != nil {
		return Accepted{}, fmt.Errorf("tenant limit: %w", err)
	}
	size := int64(len(r.Body))
	if size > limit {
		return Accepted{}, fmt.Errorf("%w: %d > %d", ErrReportTooLarge, size, limit)
	}

	sum := sha256.Sum256(r.Body)
	digest := hex.EncodeToString(sum[:])

	scanID, found, err := e.store.FindScanID(ctx, r.Scope, r.Tool, digest)
	if err != nil {
		return Accepted{}, fmt.Errorf("find job: %w", err)
	}
	if found {
		return Accepted{ScanID: scanID, SHA256: digest}, nil
	}

	key := rawstore.KeyFor(r.Scope, r.ScanID, digest)
	if err := e.raw.Put(ctx, key, bytes.NewReader(r.Body), size); err != nil {
		return Accepted{}, fmt.Errorf("put raw: %w", err)
	}

	inserted, err := e.store.InsertJob(ctx, r.Scope, r.Tool, key)
	if err != nil {
		return Accepted{}, fmt.Errorf("insert job: %w", err)
	}
	if inserted {
		return Accepted{ScanID: r.ScanID, SHA256: digest}, nil
	}

	scanID, found, err = e.store.FindScanID(ctx, r.Scope, r.Tool, digest)
	if err != nil {
		return Accepted{}, fmt.Errorf("find job: %w", err)
	}
	if !found {
		return Accepted{}, errors.New("job vanished after conflict")
	}
	return Accepted{ScanID: scanID, SHA256: digest}, nil
}
