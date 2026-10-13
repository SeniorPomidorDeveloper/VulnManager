package metrics

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/queue"
	"vulnmanager/services/normalize/internal/store"
	"vulnmanager/services/normalize/internal/worker"
)

type Metrics struct {
	jobs     *prometheus.CounterVec
	duration prometheus.Histogram
	findings prometheus.Counter
}

type jobSource struct {
	next    worker.JobSource
	metrics *Metrics
	clock   func() time.Time

	mu      sync.Mutex
	started map[uuid.UUID]time.Time
}

type findingStore struct {
	next    worker.FindingStore
	metrics *Metrics
}

type countingTx struct {
	worker.Tx
	written *int
}

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		jobs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnmanager_normalize_jobs_total",
			Help: "Ingest jobs settled by normalize, by resulting state.",
		}, []string{"state"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "vulnmanager_normalize_job_duration_seconds",
			Help:    "Time from claiming an ingest job to settling it.",
			Buckets: prometheus.DefBuckets,
		}),
		findings: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vulnmanager_normalize_findings_total",
			Help: "Findings written by normalize.",
		}),
	}
	reg.MustRegister(m.jobs, m.duration, m.findings)
	return m
}

func (m *Metrics) WrapJobs(next worker.JobSource, clock func() time.Time) worker.JobSource {
	return &jobSource{next: next, metrics: m, clock: clock, started: map[uuid.UUID]time.Time{}}
}

func (m *Metrics) WrapStore(next worker.FindingStore) worker.FindingStore {
	return findingStore{next: next, metrics: m}
}

func (j *jobSource) Claim(ctx context.Context, id queue.WorkerID, lease time.Duration) (queue.Job, bool, error) {
	job, ok, err := j.next.Claim(ctx, id, lease)
	if ok && err == nil {
		j.mu.Lock()
		j.started[job.ID] = j.clock()
		j.mu.Unlock()
	}
	return job, ok, err
}

func (j *jobSource) Finish(
	ctx context.Context, id uuid.UUID, worker queue.WorkerID, state queue.State, retryAfter time.Duration,
) (bool, error) {
	ok, err := j.next.Finish(ctx, id, worker, state, retryAfter)
	j.mu.Lock()
	started, tracked := j.started[id]
	delete(j.started, id)
	j.mu.Unlock()
	if tracked {
		j.metrics.duration.Observe(j.clock().Sub(started).Seconds())
	}
	if err == nil && ok {
		j.metrics.jobs.WithLabelValues(string(state)).Inc()
	}
	return ok, err
}

func (s findingStore) InTx(ctx context.Context, tenantID model.TenantID, fn func(worker.Tx) error) error {
	var written int
	err := s.next.InTx(ctx, tenantID, func(inner worker.Tx) error {
		return fn(countingTx{Tx: inner, written: &written})
	})
	if err == nil {
		s.metrics.findings.Add(float64(written))
	}
	return err
}

func (s findingStore) FailRun(ctx context.Context, run store.Run, reason string) error {
	return s.next.FailRun(ctx, run, reason)
}

func (t countingTx) CompleteRun(ctx context.Context, id model.ImportRunID, findings int) error {
	if err := t.Tx.CompleteRun(ctx, id, findings); err != nil {
		return err
	}
	*t.written = findings
	return nil
}
