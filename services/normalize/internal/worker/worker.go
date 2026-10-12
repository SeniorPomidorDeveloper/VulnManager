package worker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/parsers"
	"vulnmanager/services/normalize/internal/queue"
	"vulnmanager/services/normalize/internal/store"
)

const headSize = 4096

var ErrInvalidConfig = errors.New("worker: invalid config")

type Config struct {
	ID           queue.WorkerID
	Lease        time.Duration
	PollInterval time.Duration
	RetryDelay   time.Duration
	MaxAttempts  int
}

type Deps struct {
	Jobs    JobSource
	Raw     RawReader
	Store   FindingStore
	Parsers *parsers.Registry
	Clock   func() time.Time
	Log     *slog.Logger
}

type JobSource interface {
	Claim(ctx context.Context, worker queue.WorkerID, lease time.Duration) (queue.Job, bool, error)
	Finish(ctx context.Context, id uuid.UUID, worker queue.WorkerID, state queue.State, retryAfter time.Duration) (bool, error)
}

type RawReader interface {
	Get(ctx context.Context, key model.RawKey) (io.ReadCloser, error)
}

type Tx interface {
	StartRun(ctx context.Context, run store.Run) (model.ImportRunID, error)
	AddFinding(ctx context.Context, finding model.Finding) error
	CompleteRun(ctx context.Context, id model.ImportRunID, findings int) error
}

type FindingStore interface {
	InTx(ctx context.Context, tenantID model.TenantID, fn func(Tx) error) error
	FailRun(ctx context.Context, run store.Run, reason string) error
}

type Worker struct {
	cfg  Config
	deps Deps
}

type storeAdapter struct {
	store *store.Store
}

func NewStore(s *store.Store) FindingStore {
	return storeAdapter{store: s}
}

func (a storeAdapter) InTx(ctx context.Context, tenantID model.TenantID, fn func(Tx) error) error {
	return a.store.InTx(ctx, tenantID, func(tx *store.Tx) error { return fn(tx) })
}

func (a storeAdapter) FailRun(ctx context.Context, run store.Run, reason string) error {
	return a.store.FailRun(ctx, run, reason)
}

func (c Config) valid() bool {
	durations := []time.Duration{c.Lease, c.PollInterval, c.RetryDelay}
	return c.ID != "" && c.MaxAttempts > 0 && !slices.ContainsFunc(durations, func(d time.Duration) bool { return d <= 0 })
}

func (d Deps) valid() bool {
	return d.Jobs != nil && d.Raw != nil && d.Store != nil && d.Parsers != nil && d.Clock != nil
}

func New(cfg Config, deps Deps) (*Worker, error) {
	if !cfg.valid() || !deps.valid() {
		return nil, ErrInvalidConfig
	}
	if deps.Log == nil {
		deps.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Worker{cfg: cfg, deps: deps}, nil
}

func (w *Worker) Run(ctx context.Context) {
	for ctx.Err() == nil {
		processed, err := w.RunOnce(ctx)
		if err != nil {
			w.deps.Log.Error("worker iteration failed", "error", err)
		}
		if processed && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
		case <-time.After(w.cfg.PollInterval):
		}
	}
}

func (w *Worker) RunOnce(ctx context.Context) (bool, error) {
	job, ok, err := w.deps.Jobs.Claim(ctx, w.cfg.ID, w.cfg.Lease)
	if err != nil || !ok {
		return false, err
	}
	run := store.Run{
		Scope:  job.Scope,
		Tool:   job.Tool,
		ScanID: job.ScanID,
		RawKey: job.RawKey.String(),
		SHA256: job.RawKey.SHA256,
	}
	procErr := w.process(ctx, job, run)
	return true, w.settle(ctx, job, run, procErr)
}

func (w *Worker) process(ctx context.Context, job queue.Job, run store.Run) error {
	object, err := w.deps.Raw.Get(ctx, job.RawKey)
	if err != nil {
		return fmt.Errorf("read raw: %w", err)
	}
	defer object.Close()

	reader := bufio.NewReaderSize(object, headSize)
	head, err := reader.Peek(headSize)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read head: %w", err)
	}
	parser := w.deps.Parsers.Detect(head)
	meta := parsers.ScanMeta{Tool: job.Tool, ScanID: job.ScanID}

	err = w.deps.Store.InTx(ctx, job.Scope.TenantID, func(tx Tx) error {
		return w.write(ctx, tx, job, run, parser, reader, meta)
	})
	if errors.Is(err, store.ErrAlreadyCompleted) {
		return nil
	}
	return err
}

func (w *Worker) write(
	ctx context.Context, tx Tx, job queue.Job, run store.Run,
	parser parsers.Parser, reader io.Reader, meta parsers.ScanMeta,
) error {
	runID, err := tx.StartRun(ctx, run)
	if err != nil {
		return err
	}
	algoVersion := fmt.Sprintf("%s@%s", parser.ID(), parser.Version())
	detectedAt := w.deps.Clock()
	count := 0
	for raw, err := range parser.Parse(ctx, reader, meta) {
		if err != nil {
			return fmt.Errorf("parse: %w", err)
		}
		finding := model.Finding{
			ImportRunID:   runID,
			Scope:         job.Scope,
			ToolFindingID: raw.ToolFindingID,
			Kind:          raw.Kind,
			Title:         raw.Title,
			Description:   raw.Description,
			SeverityRaw:   raw.SeverityRaw,
			Location:      raw.Location,
			Raw:           raw.Raw,
			Provenance:    model.Provenance{Tool: job.Tool, ScanID: job.ScanID},
			AlgoVersion:   algoVersion,
			DetectedAt:    detectedAt,
			Diagnostics:   raw.Diagnostics,
		}
		if err := tx.AddFinding(ctx, finding); err != nil {
			return err
		}
		count++
	}
	return tx.CompleteRun(ctx, runID, count)
}

func (w *Worker) settle(ctx context.Context, job queue.Job, run store.Run, procErr error) error {
	ctx = context.WithoutCancel(ctx)
	if procErr == nil {
		return w.finish(ctx, job, queue.StateDone, 0)
	}
	w.deps.Log.Warn("job failed", "job", job.ID, "attempts", job.Attempts, "error", procErr)
	failErr := w.deps.Store.FailRun(ctx, run, procErr.Error())
	state, delay := queue.StatePending, w.cfg.RetryDelay*time.Duration(job.Attempts)
	if job.Attempts >= w.cfg.MaxAttempts {
		state, delay = queue.StateDead, 0
	}
	return errors.Join(failErr, w.finish(ctx, job, state, delay))
}

func (w *Worker) finish(ctx context.Context, job queue.Job, state queue.State, delay time.Duration) error {
	ok, err := w.deps.Jobs.Finish(ctx, job.ID, w.cfg.ID, state, delay)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("job %s: lease lost before finish", job.ID)
	}
	return nil
}
