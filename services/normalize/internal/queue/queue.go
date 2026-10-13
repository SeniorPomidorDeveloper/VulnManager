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
	State       string
	WorkerID    string
	ClaimStatus string
)

const (
	StateDone    State = "done"
	StatePending State = "pending"
	StateDead    State = "dead"

	ClaimClaimed  ClaimStatus = "claimed"
	ClaimBusy     ClaimStatus = "busy"
	ClaimFinished ClaimStatus = "finished"
	ClaimMissing  ClaimStatus = "missing"
)

var finishedStates = map[string]ClaimStatus{
	string(StateDone): ClaimFinished,
	string(StateDead): ClaimFinished,
}

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

func (q *Queue) Claim(ctx context.Context, id uuid.UUID, worker WorkerID, lease time.Duration) (Job, ClaimStatus, error) {
	row, err := q.queries.ClaimIngestJob(ctx, db.ClaimIngestJobParams{ID: id, Worker: text(worker), Lease: interval(lease)})
	if errors.Is(err, pgx.ErrNoRows) {
		status, err := q.unclaimedStatus(ctx, id)
		return Job{}, status, err
	}
	if err != nil {
		return Job{}, "", fmt.Errorf("claim ingest job %s: %w", id, err)
	}
	scope, err := model.NewScope(model.TenantID(row.TenantID), model.ProductID(row.ProductID), model.ContextID(row.ContextID))
	if err != nil {
		return Job{}, "", fmt.Errorf("job %s scope: %w", id, err)
	}
	scanID := model.ScanID(row.ScanID)
	return Job{
		ID:       row.ID,
		Scope:    scope,
		Tool:     model.ToolName(row.Tool),
		ScanID:   scanID,
		RawKey:   model.RawKeyFor(scope, scanID, row.Sha256),
		Attempts: int(row.Attempts),
	}, ClaimClaimed, nil
}

func (q *Queue) Finish(ctx context.Context, id uuid.UUID, worker WorkerID, state State) (bool, error) {
	updated, err := q.queries.FinishIngestJob(ctx, db.FinishIngestJobParams{ID: id, Worker: text(worker), State: string(state)})
	if err != nil {
		return false, fmt.Errorf("finish ingest job %s: %w", id, err)
	}
	return updated > 0, nil
}

func (q *Queue) unclaimedStatus(ctx context.Context, id uuid.UUID) (ClaimStatus, error) {
	state, err := q.queries.GetIngestJobState(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimMissing, nil
	}
	if err != nil {
		return "", fmt.Errorf("ingest job %s state: %w", id, err)
	}
	if status, ok := finishedStates[state]; ok {
		return status, nil
	}
	return ClaimBusy, nil
}

func text(worker WorkerID) pgtype.Text {
	return pgtype.Text{String: string(worker), Valid: true}
}

func interval(d time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: d.Microseconds(), Valid: true}
}
