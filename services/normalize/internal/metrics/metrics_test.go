package metrics

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/queue"
	"vulnmanager/services/normalize/internal/store"
	"vulnmanager/services/normalize/internal/worker"
)

type stubJobs struct {
	job queue.Job
}

type stubTx struct {
	worker.Tx
}

type stubStore struct {
	err error
}

func (s stubJobs) Claim(context.Context, uuid.UUID, queue.WorkerID, time.Duration) (queue.Job, queue.ClaimStatus, error) {
	return s.job, queue.ClaimClaimed, nil
}

func (stubJobs) Finish(context.Context, uuid.UUID, queue.WorkerID, queue.State) (bool, error) {
	return true, nil
}

func (stubTx) CompleteRun(context.Context, model.ImportRunID, int) error {
	return nil
}

func (s stubStore) InTx(_ context.Context, fn func(worker.Tx) error) error {
	if err := fn(stubTx{}); err != nil {
		return err
	}
	return s.err
}

func (stubStore) UnpublishedRun(context.Context, store.Run) (model.ImportRunID, bool, error) {
	return "", false, nil
}

func (stubStore) MarkPublished(context.Context, model.TenantID, model.ImportRunID) (bool, error) {
	return true, nil
}

func (stubStore) FailRun(context.Context, store.Run, string) error {
	return nil
}

func TestJobs_CountByStateAndObserveDuration(t *testing.T) {
	m := New(prometheus.NewRegistry())
	now := time.Unix(0, 0)
	clock := func() time.Time { now = now.Add(time.Second); return now }
	jobs := m.WrapJobs(stubJobs{job: queue.Job{ID: uuid.New()}}, clock)

	job, _, _ := jobs.Claim(context.Background(), uuid.New(), "w", time.Minute)
	if _, err := jobs.Finish(context.Background(), job.ID, "w", queue.StateDone); err != nil {
		t.Fatal(err)
	}

	if got := testutil.ToFloat64(m.jobs.WithLabelValues("done")); got != 1 {
		t.Fatalf("done jobs = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(m.duration); got != 1 {
		t.Fatalf("duration series = %d, want 1", got)
	}
}

func TestStore_CountsFindingsOnlyAfterSuccessfulTx(t *testing.T) {
	m := New(prometheus.NewRegistry())
	complete := func(tx worker.Tx) error { return tx.CompleteRun(context.Background(), "run", 3) }

	_ = m.WrapStore(stubStore{err: errors.New("commit failed")}).InTx(context.Background(), complete)
	if got := testutil.ToFloat64(m.findings); got != 0 {
		t.Fatalf("findings after failed commit = %v, want 0", got)
	}

	if err := m.WrapStore(stubStore{}).InTx(context.Background(), complete); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(m.findings); got != 3 {
		t.Fatalf("findings = %v, want 3", got)
	}
}
