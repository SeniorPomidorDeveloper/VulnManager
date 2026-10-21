package worker

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/adapters"
	"vulnmanager/services/normalize/internal/events"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/normalizers/blocks"
	"vulnmanager/services/normalize/internal/parsers"
	"vulnmanager/services/normalize/internal/queue"
	"vulnmanager/services/normalize/internal/store"
)

const sarifReport = `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","semanticVersion":"1.180.0","rules":[]}},"results":[
{"ruleId":"r1","message":{"text":"first"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]},
{"ruleId":"r2","message":{"text":"second"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.go"},"region":{"startLine":2}}}]}]}]}`

type fakeJobs struct {
	job      queue.Job
	status   queue.ClaimStatus
	finished []queue.State
}

type fakeRaw struct {
	body string
	err  error
}

type fakeTx struct {
	started     []store.Run
	findings    []model.Finding
	completed   []int
	alreadyDone bool
}

type fakeStore struct {
	tx          *fakeTx
	failed      []string
	published   []events.Event
	marked      []model.ImportRunID
	publishErr  error
	unpublished model.ImportRunID
}

func (j *fakeJobs) Claim(context.Context, uuid.UUID, queue.WorkerID, time.Duration) (queue.Job, queue.ClaimStatus, error) {
	return j.job, j.status, nil
}

func (j *fakeJobs) Finish(_ context.Context, _ uuid.UUID, _ queue.WorkerID, state queue.State) (bool, error) {
	j.finished = append(j.finished, state)
	return true, nil
}

func (r fakeRaw) Get(context.Context, model.RawKey) (io.ReadCloser, error) {
	if r.err != nil {
		return nil, r.err
	}
	return io.NopCloser(strings.NewReader(r.body)), nil
}

func (t *fakeTx) StartRun(_ context.Context, run store.Run) (model.ImportRunID, error) {
	if t.alreadyDone {
		return "", store.ErrAlreadyCompleted
	}
	t.started = append(t.started, run)
	return "run-1", nil
}

func (t *fakeTx) AddFinding(_ context.Context, finding model.Finding) error {
	t.findings = append(t.findings, finding)
	return nil
}

func (t *fakeTx) CompleteRun(_ context.Context, _ model.ImportRunID, findings int) error {
	t.completed = append(t.completed, findings)
	return nil
}

func (s *fakeStore) InTx(_ context.Context, fn func(Tx) error) error {
	return fn(s.tx)
}

func (s *fakeStore) Publish(_ context.Context, event events.Event) error {
	if s.publishErr != nil {
		return s.publishErr
	}
	s.published = append(s.published, event)
	return nil
}

func (s *fakeStore) UnpublishedRun(context.Context, store.Run) (model.ImportRunID, bool, error) {
	return s.unpublished, s.unpublished != "", nil
}

func (s *fakeStore) MarkPublished(_ context.Context, _ model.TenantID, id model.ImportRunID) (bool, error) {
	s.marked = append(s.marked, id)
	return true, nil
}

func (s *fakeStore) FailRun(_ context.Context, _ store.Run, reason string) error {
	s.failed = append(s.failed, reason)
	return nil
}

func newAdapters(t *testing.T) *adapters.Registry {
	t.Helper()
	scale := blocks.SeverityScale{"warning": model.SeverityMedium}
	chain, err := normalizers.NewChain(normalizers.NewSeverity(blocks.SeverityByPriority(scale, nil, blocks.SeverityFromLabel)))
	if err != nil {
		t.Fatal(err)
	}
	sarif := adapters.Adapter{Parser: parsers.NewSARIF(), Normalizer: chain}
	registry, err := adapters.New(
		map[model.ToolName]adapters.Adapter{"semgrep": sarif},
		adapters.Adapter{Parser: parsers.NewGenericJSON(), Normalizer: chain},
	)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func newWorker(t *testing.T, job queue.Job, raw fakeRaw) (*Worker, *fakeJobs, *fakeStore) {
	t.Helper()
	jobs := &fakeJobs{job: job, status: queue.ClaimClaimed}
	findings := &fakeStore{tx: &fakeTx{}}
	w, err := New(
		Config{ID: "w1", Lease: time.Minute, RetryDelay: time.Minute, MaxAttempts: 3},
		Deps{
			Jobs:     jobs,
			Raw:      raw,
			Store:    findings,
			Adapters: newAdapters(t),
			Events:   findings,
			Clock:    func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return w, jobs, findings
}

func testJob(attempts int) queue.Job {
	scope, _ := model.NewScope("t1", "p1", "c1")
	return queue.Job{
		ID:       uuid.New(),
		Scope:    scope,
		Tool:     "semgrep",
		ScanID:   "scan-1",
		RawKey:   model.RawKeyFor(scope, "scan-1", "abcd"),
		Attempts: attempts,
	}
}

func TestHandle_WritesFindingsAndAcks(t *testing.T) {
	job := testJob(1)
	w, jobs, findings := newWorker(t, job, fakeRaw{body: sarifReport})

	outcome, err := w.Handle(context.Background(), job.ID)

	if err != nil || outcome.Action != ActionAck {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	if got := findings.tx.completed; len(got) != 1 || got[0] != 2 {
		t.Fatalf("completed = %v, want [2]", got)
	}
	first := findings.tx.findings[0]
	if first.Scope.TenantID != "t1" || first.ImportRunID != "run-1" || first.Provenance.ScanID != "scan-1" || first.Provenance.ToolVersion != "1.180.0" {
		t.Fatalf("unexpected finding: %+v", first)
	}
	if !strings.HasPrefix(first.AlgoVersion, string(parsers.NewSARIF().ID())+"@") ||
		!strings.HasSuffix(first.AlgoVersion, "/severity@2(label)") {
		t.Fatalf("algo version = %q", first.AlgoVersion)
	}
	if first.Severity != model.SeverityMedium {
		t.Fatalf("severity = %v, want medium", first.Severity)
	}
	if len(jobs.finished) != 1 || jobs.finished[0] != queue.StateDone {
		t.Fatalf("finished = %v", jobs.finished)
	}
}

func TestHandle_UnclaimedJobIsSkipped(t *testing.T) {
	tests := map[queue.ClaimStatus]Action{
		queue.ClaimMissing:  ActionAck,
		queue.ClaimFinished: ActionAck,
		queue.ClaimBusy:     ActionRetry,
	}
	for status, want := range tests {
		t.Run(string(status), func(t *testing.T) {
			job := testJob(1)
			w, jobs, findings := newWorker(t, job, fakeRaw{body: sarifReport})
			jobs.status = status

			outcome, err := w.Handle(context.Background(), job.ID)

			if err != nil || outcome.Action != want || len(findings.tx.findings) != 0 || len(jobs.finished) != 0 {
				t.Fatalf("outcome=%+v err=%v findings=%d finished=%v", outcome, err, len(findings.tx.findings), jobs.finished)
			}
		})
	}
}

func TestHandle_AlreadyProcessedReportIsAcked(t *testing.T) {
	job := testJob(1)
	w, jobs, findings := newWorker(t, job, fakeRaw{body: sarifReport})
	findings.tx.alreadyDone = true

	outcome, err := w.Handle(context.Background(), job.ID)

	if err != nil || outcome.Action != ActionAck || jobs.finished[0] != queue.StateDone || len(findings.failed) != 0 {
		t.Fatalf("outcome=%+v err=%v finished=%v failed=%v", outcome, err, jobs.finished, findings.failed)
	}
}

func TestHandle_FailureRetriesWithGrowingDelay(t *testing.T) {
	job := testJob(2)
	w, jobs, findings := newWorker(t, job, fakeRaw{err: errors.New("boom")})

	outcome, err := w.Handle(context.Background(), job.ID)

	want := Outcome{Action: ActionRetry, Delay: 2 * time.Minute}
	if err != nil || outcome != want || jobs.finished[0] != queue.StatePending || len(findings.failed) != 1 {
		t.Fatalf("outcome=%+v err=%v finished=%v failed=%v", outcome, err, jobs.finished, findings.failed)
	}
}

func TestHandle_FailureOnLastAttemptIsDead(t *testing.T) {
	job := testJob(3)
	w, jobs, _ := newWorker(t, job, fakeRaw{err: errors.New("boom")})

	outcome, err := w.Handle(context.Background(), job.ID)

	if err != nil || outcome.Action != ActionDead || jobs.finished[0] != queue.StateDead {
		t.Fatalf("outcome=%+v err=%v finished=%v", outcome, err, jobs.finished)
	}
}

func TestHandle_BrokenReportFailsTheRun(t *testing.T) {
	job := testJob(1)
	w, jobs, findings := newWorker(t, job, fakeRaw{body: `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs": [`})

	outcome, err := w.Handle(context.Background(), job.ID)

	if err != nil || outcome.Action != ActionRetry || jobs.finished[0] != queue.StatePending || len(findings.failed) != 1 {
		t.Fatalf("outcome=%+v err=%v finished=%v failed=%v", outcome, err, jobs.finished, findings.failed)
	}
}

func TestNew_RejectsIncompleteConfig(t *testing.T) {
	if _, err := New(Config{}, Deps{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("got %v, want ErrInvalidConfig", err)
	}
}

func TestHandle_PublishesImportCompletedAndMarksTheRun(t *testing.T) {
	job := testJob(1)
	w, _, findings := newWorker(t, job, fakeRaw{body: sarifReport})

	if outcome, err := w.Handle(context.Background(), job.ID); err != nil || outcome.Action != ActionAck {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}

	want := events.Event{RunID: "run-1", Scope: job.Scope, Tool: job.Tool, ScanID: job.ScanID}
	if len(findings.published) != 1 || findings.published[0] != want {
		t.Fatalf("published %+v, want %+v", findings.published, want)
	}
	if len(findings.marked) != 1 || findings.marked[0] != "run-1" {
		t.Fatalf("marked %v", findings.marked)
	}
}

func TestHandle_FailedPublicationRetriesTheJob(t *testing.T) {
	job := testJob(1)
	w, jobs, findings := newWorker(t, job, fakeRaw{body: sarifReport})
	findings.publishErr = errors.New("broker down")

	outcome, err := w.Handle(context.Background(), job.ID)

	if err != nil || outcome.Action != ActionRetry {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	if len(findings.marked) != 0 || len(jobs.finished) != 1 || jobs.finished[0] != queue.StatePending {
		t.Fatalf("marked %v finished %v", findings.marked, jobs.finished)
	}
}

func TestHandle_AlreadyCompletedAndPublishedRunIsNotPublishedAgain(t *testing.T) {
	job := testJob(1)
	w, _, findings := newWorker(t, job, fakeRaw{body: sarifReport})
	findings.tx.alreadyDone = true

	if _, err := w.Handle(context.Background(), job.ID); err != nil {
		t.Fatalf("handle: %v", err)
	}

	if len(findings.published) != 0 || len(findings.marked) != 0 {
		t.Fatalf("published %v marked %v", findings.published, findings.marked)
	}
}

func TestHandle_RedeliveredJobPublishesTheMissedEvent(t *testing.T) {
	job := testJob(2)
	w, jobs, findings := newWorker(t, job, fakeRaw{body: sarifReport})
	findings.tx.alreadyDone = true
	findings.unpublished = "run-7"

	outcome, err := w.Handle(context.Background(), job.ID)

	if err != nil || outcome.Action != ActionAck {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	want := events.Event{RunID: "run-7", Scope: job.Scope, Tool: job.Tool, ScanID: job.ScanID}
	if len(findings.published) != 1 || findings.published[0] != want || len(findings.marked) != 1 || findings.marked[0] != "run-7" {
		t.Fatalf("published %+v marked %v", findings.published, findings.marked)
	}
	if len(jobs.finished) != 1 || jobs.finished[0] != queue.StateDone {
		t.Fatalf("finished %v", jobs.finished)
	}
}
