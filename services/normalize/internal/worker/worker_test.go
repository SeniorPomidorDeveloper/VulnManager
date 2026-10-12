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
	"vulnmanager/services/normalize/internal/parsers"
	"vulnmanager/services/normalize/internal/queue"
	"vulnmanager/services/normalize/internal/store"
)

const sarifReport = `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[]}},"results":[
{"ruleId":"r1","message":{"text":"first"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]},
{"ruleId":"r2","message":{"text":"second"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.go"},"region":{"startLine":2}}}]}]}]}`

type finishCall struct {
	state queue.State
	delay time.Duration
}

type fakeJobs struct {
	job      *queue.Job
	finished []finishCall
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
	tx     *fakeTx
	failed []string
}

func (j *fakeJobs) Claim(context.Context, queue.WorkerID, time.Duration) (queue.Job, bool, error) {
	if j.job == nil {
		return queue.Job{}, false, nil
	}
	job := *j.job
	j.job = nil
	return job, true, nil
}

func (j *fakeJobs) Finish(_ context.Context, _ uuid.UUID, _ queue.WorkerID, state queue.State, delay time.Duration) (bool, error) {
	j.finished = append(j.finished, finishCall{state: state, delay: delay})
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

func (s *fakeStore) InTx(_ context.Context, _ model.TenantID, fn func(Tx) error) error {
	return fn(s.tx)
}

func (s *fakeStore) FailRun(_ context.Context, _ store.Run, reason string) error {
	s.failed = append(s.failed, reason)
	return nil
}

func newWorker(t *testing.T, job queue.Job, raw fakeRaw) (*Worker, *fakeJobs, *fakeStore) {
	t.Helper()
	registry := parsers.NewRegistry(parsers.NewGenericJSON())
	if err := registry.Register(parsers.NewSARIF()); err != nil {
		t.Fatal(err)
	}
	jobs := &fakeJobs{job: &job}
	findings := &fakeStore{tx: &fakeTx{}}
	w, err := New(
		Config{ID: "w1", Lease: time.Minute, PollInterval: time.Second, RetryDelay: time.Minute, MaxAttempts: 3},
		Deps{
			Jobs:    jobs,
			Raw:     raw,
			Store:   findings,
			Parsers: registry,
			Clock:   func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
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

func TestRunOnce_WritesFindingsAndFinishesDone(t *testing.T) {
	w, jobs, findings := newWorker(t, testJob(1), fakeRaw{body: sarifReport})

	processed, err := w.RunOnce(context.Background())

	if err != nil || !processed {
		t.Fatalf("processed=%v err=%v", processed, err)
	}
	if got := findings.tx.completed; len(got) != 1 || got[0] != 2 {
		t.Fatalf("completed = %v, want [2]", got)
	}
	first := findings.tx.findings[0]
	if first.Scope.TenantID != "t1" || first.ImportRunID != "run-1" || first.Provenance.ScanID != "scan-1" {
		t.Fatalf("unexpected finding: %+v", first)
	}
	if !strings.HasPrefix(first.AlgoVersion, string(parsers.NewSARIF().ID())+"@") {
		t.Fatalf("algo version = %q", first.AlgoVersion)
	}
	if want := (finishCall{state: queue.StateDone}); jobs.finished[0] != want {
		t.Fatalf("finish = %+v, want %+v", jobs.finished[0], want)
	}
}

func TestRunOnce_EmptyQueueDoesNothing(t *testing.T) {
	w, jobs, _ := newWorker(t, testJob(1), fakeRaw{})
	jobs.job = nil

	processed, err := w.RunOnce(context.Background())

	if err != nil || processed || len(jobs.finished) != 0 {
		t.Fatalf("processed=%v err=%v finished=%v", processed, err, jobs.finished)
	}
}

func TestRunOnce_AlreadyProcessedReportIsDone(t *testing.T) {
	w, jobs, findings := newWorker(t, testJob(1), fakeRaw{body: sarifReport})
	findings.tx.alreadyDone = true

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if jobs.finished[0].state != queue.StateDone || len(findings.failed) != 0 {
		t.Fatalf("finished=%+v failed=%v", jobs.finished, findings.failed)
	}
}

func TestRunOnce_FailureRetriesWithGrowingDelay(t *testing.T) {
	w, jobs, findings := newWorker(t, testJob(2), fakeRaw{err: errors.New("boom")})

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	want := finishCall{state: queue.StatePending, delay: 2 * time.Minute}
	if jobs.finished[0] != want || len(findings.failed) != 1 {
		t.Fatalf("finished=%+v failed=%v", jobs.finished, findings.failed)
	}
}

func TestRunOnce_FailureOnLastAttemptIsDead(t *testing.T) {
	w, jobs, _ := newWorker(t, testJob(3), fakeRaw{err: errors.New("boom")})

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if want := (finishCall{state: queue.StateDead}); jobs.finished[0] != want {
		t.Fatalf("finish = %+v, want %+v", jobs.finished[0], want)
	}
}

func TestRunOnce_BrokenReportFailsTheRun(t *testing.T) {
	w, jobs, findings := newWorker(t, testJob(1), fakeRaw{body: `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs": [`})

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if jobs.finished[0].state != queue.StatePending || len(findings.failed) != 1 {
		t.Fatalf("finished=%+v failed=%v", jobs.finished, findings.failed)
	}
}

func TestNew_RejectsIncompleteConfig(t *testing.T) {
	if _, err := New(Config{}, Deps{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("got %v, want ErrInvalidConfig", err)
	}
}
