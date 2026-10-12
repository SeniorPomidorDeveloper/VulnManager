package queue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/gen/db"
)

type (
	State    string
	WorkerID string
)

const (
	StateDone    State = "done"
	StatePending State = "pending"
	StateDead    State = "dead"
)

type Job struct {
	ID       uuid.UUID
	Scope    model.Scope
	Tool     model.ToolName
	ScanID   model.ScanID
	RawKey   model.RawKey
	Attempts int
}

type Queue struct {
	queries *db.Queries
}

func New(queries *db.Queries) *Queue {
	return &Queue{queries: queries}
}

func (q *Queue) Claim(ctx context.Context, worker WorkerID, lease time.Duration) (Job, bool, error) {
	row, err := q.queries.ClaimIngestJob(ctx, db.ClaimIngestJobParams{PWorker: string(worker), PLease: interval(lease)})
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, false, nil
	}
	if err != nil {
		return Job{}, false, fmt.Errorf("claim ingest job: %w", err)
	}
	scope, err := model.NewScope(model.TenantID(row.TenantID), model.ProductID(row.ProductID), model.ContextID(row.ContextID))
	if err != nil {
		return Job{}, false, fmt.Errorf("job %s scope: %w", row.ID, err)
	}
	scanID := model.ScanID(row.ScanID)
	return Job{
		ID:       row.ID,
		Scope:    scope,
		Tool:     model.ToolName(row.Tool),
		ScanID:   scanID,
		RawKey:   model.RawKeyFor(scope, scanID, row.Sha256),
		Attempts: int(row.Attempts),
	}, true, nil
}

func (q *Queue) Finish(ctx context.Context, id uuid.UUID, worker WorkerID, state State, retryAfter time.Duration) (bool, error) {
	ok, err := q.queries.FinishIngestJob(ctx, db.FinishIngestJobParams{
		PID:         id,
		PWorker:     string(worker),
		PState:      string(state),
		PRetryAfter: interval(retryAfter),
	})
	if err != nil {
		return false, fmt.Errorf("finish ingest job %s: %w", id, err)
	}
	return ok, nil
}

func interval(d time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: d.Microseconds(), Valid: true}
}
