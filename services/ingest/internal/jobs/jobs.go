package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"

	"vulnmanager/modules/model"
)

type JobState string

const StatePending JobState = "pending"

var (
	ErrReportTooLarge = errors.New("jobs: report exceeds tenant limit")
	ErrTenantNotFound = errors.New("jobs: tenant not found")
	ErrNotPublished   = errors.New("jobs: event is not published")
)

type Report struct {
	Scope  model.Scope
	Tool   model.ToolName
	ScanID model.ScanID
	Body   []byte
}

type Accepted struct {
	ScanID model.ScanID
	SHA256 string
}

type Job struct {
	ID     uuid.UUID
	ScanID model.ScanID
	State  JobState
}

type Event struct {
	JobID  uuid.UUID
	Scope  model.Scope
	Tool   model.ToolName
	RawKey model.RawKey
}

type RawWriter interface {
	Put(ctx context.Context, key model.RawKey, r io.Reader, size int64) error
}

type Publisher interface {
	Publish(ctx context.Context, event Event) error
}

type Store interface {
	MaxReportBytes(ctx context.Context, tenantID model.TenantID) (int64, error)
	FindJob(ctx context.Context, scope model.Scope, tool model.ToolName, sha256 string) (Job, bool, error)
	InsertJob(ctx context.Context, scope model.Scope, tool model.ToolName, key model.RawKey) (uuid.UUID, bool, error)
}

type Enqueuer struct {
	store     Store
	raw       RawWriter
	publisher Publisher
}

func NewEnqueuer(store Store, raw RawWriter, publisher Publisher) *Enqueuer {
	return &Enqueuer{store: store, raw: raw, publisher: publisher}
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

	job, found, err := e.store.FindJob(ctx, r.Scope, r.Tool, digest)
	if err != nil {
		return Accepted{}, fmt.Errorf("find job: %w", err)
	}
	if found {
		return e.redeliver(ctx, r, job, digest)
	}

	key := model.RawKeyFor(r.Scope, r.ScanID, digest)
	if err := e.raw.Put(ctx, key, bytes.NewReader(r.Body), size); err != nil {
		return Accepted{}, fmt.Errorf("put raw: %w", err)
	}

	jobID, inserted, err := e.store.InsertJob(ctx, r.Scope, r.Tool, key)
	if err != nil {
		return Accepted{}, fmt.Errorf("insert job: %w", err)
	}
	if !inserted {
		return e.afterConflict(ctx, r, digest)
	}
	if err := e.publish(ctx, jobID, r, key); err != nil {
		return Accepted{}, err
	}
	return Accepted{ScanID: r.ScanID, SHA256: digest}, nil
}

func (e *Enqueuer) afterConflict(ctx context.Context, r Report, digest string) (Accepted, error) {
	job, found, err := e.store.FindJob(ctx, r.Scope, r.Tool, digest)
	if err != nil {
		return Accepted{}, fmt.Errorf("find job: %w", err)
	}
	if !found {
		return Accepted{}, errors.New("job vanished after conflict")
	}
	return e.redeliver(ctx, r, job, digest)
}

func (e *Enqueuer) redeliver(ctx context.Context, r Report, job Job, digest string) (Accepted, error) {
	if job.State == StatePending {
		if err := e.publish(ctx, job.ID, r, model.RawKeyFor(r.Scope, job.ScanID, digest)); err != nil {
			return Accepted{}, err
		}
	}
	return Accepted{ScanID: job.ScanID, SHA256: digest}, nil
}

func (e *Enqueuer) publish(ctx context.Context, jobID uuid.UUID, r Report, key model.RawKey) error {
	err := e.publisher.Publish(ctx, Event{JobID: jobID, Scope: r.Scope, Tool: r.Tool, RawKey: key})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotPublished, err)
	}
	return nil
}
