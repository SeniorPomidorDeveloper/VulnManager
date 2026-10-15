package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/adapters"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/parsers"
	"vulnmanager/services/normalize/internal/queue"
	"vulnmanager/services/normalize/internal/store"
)

var ErrInvalidConfig = errors.New("worker: invalid config")

type Action string

const (
	ActionAck   Action = "ack"
	ActionRetry Action = "retry"
	ActionDead  Action = "dead"
)

var skipActions = map[queue.ClaimStatus]Action{
	queue.ClaimMissing:  ActionAck,
	queue.ClaimFinished: ActionAck,
	queue.ClaimBusy:     ActionRetry,
}

type Outcome struct {
	Action Action
	Delay  time.Duration
}

type Config struct {
	ID          queue.WorkerID
	Lease       time.Duration
	RetryDelay  time.Duration
	MaxAttempts int
}

type Deps struct {
	Jobs     JobSource
	Raw      RawReader
	Store    FindingStore
	Adapters *adapters.Registry
	Clock    func() time.Time
	Log      *slog.Logger
}

type JobSource interface {
	Claim(ctx context.Context, id uuid.UUID, worker queue.WorkerID, lease time.Duration) (queue.Job, queue.ClaimStatus, error)
	Finish(ctx context.Context, id uuid.UUID, worker queue.WorkerID, state queue.State) (bool, error)
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
	InTx(ctx context.Context, fn func(Tx) error) error
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

func (a storeAdapter) InTx(ctx context.Context, fn func(Tx) error) error {
	return a.store.InTx(ctx, func(tx *store.Tx) error { return fn(tx) })
}

func (a storeAdapter) FailRun(ctx context.Context, run store.Run, reason string) error {
	return a.store.FailRun(ctx, run, reason)
}

func (c Config) valid() bool {
	durations := []time.Duration{c.Lease, c.RetryDelay}
	return c.ID != "" && c.MaxAttempts > 0 && !slices.ContainsFunc(durations, func(d time.Duration) bool { return d <= 0 })
}

func (d Deps) valid() bool {
	return d.Jobs != nil && d.Raw != nil && d.Store != nil && d.Adapters != nil && d.Clock != nil
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

func (w *Worker) Handle(ctx context.Context, id uuid.UUID) (Outcome, error) {
	job, status, err := w.deps.Jobs.Claim(ctx, id, w.cfg.ID, w.cfg.Lease)
	if err != nil {
		return Outcome{}, err
	}
	if status != queue.ClaimClaimed {
		return w.skipped(id, status), nil
	}
	run := store.Run{
		Scope:  job.Scope,
		Tool:   job.Tool,
		ScanID: job.ScanID,
		RawKey: job.RawKey.String(),
		SHA256: job.RawKey.SHA256,
	}
	return w.settle(ctx, job, run, w.process(ctx, job, run))
}

func (w *Worker) skipped(id uuid.UUID, status queue.ClaimStatus) Outcome {
	action, known := skipActions[status]
	if !known {
		action = ActionRetry
	}
	w.deps.Log.Info("job not claimed", "job", id, "status", status, "action", action)
	return Outcome{Action: action, Delay: w.cfg.RetryDelay}
}

func (w *Worker) process(ctx context.Context, job queue.Job, run store.Run) error {
	object, err := w.deps.Raw.Get(ctx, job.RawKey)
	if err != nil {
		return fmt.Errorf("read raw: %w", err)
	}
	defer object.Close()

	resolution := w.deps.Adapters.Resolve(job.Tool)
	meta := parsers.ScanMeta{Tool: job.Tool, ScanID: job.ScanID}

	err = w.deps.Store.InTx(ctx, func(tx Tx) error {
		return w.write(ctx, tx, job, run, resolution, object, meta)
	})
	if errors.Is(err, store.ErrAlreadyCompleted) {
		return nil
	}
	return err
}

func (w *Worker) write(
	ctx context.Context, tx Tx, job queue.Job, run store.Run,
	resolution adapters.Resolution, reader io.Reader, meta parsers.ScanMeta,
) error {
	runID, err := tx.StartRun(ctx, run)
	if err != nil {
		return err
	}
	parser, normalizer := resolution.Adapter.Parser, resolution.Adapter.Normalizer
	algoVersion := algoVersion(parser, normalizer)
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
			VulnIDRaw:     raw.VulnIDRaw,
			PURLRaw:       raw.PURLRaw,
			CVSSRaw:       raw.CVSSVectors,
			ScannerScore:  raw.ScannerScore,
			RuleID:        raw.RuleID,
			CWERaw:        raw.CWEs,
			Location:      raw.Location,
			Raw:           raw.Raw,
			Provenance:    model.Provenance{Tool: job.Tool, ToolVersion: raw.ToolVersion, ScanID: job.ScanID},
			AlgoVersion:   algoVersion,
			DetectedAt:    detectedAt,
			Diagnostics:   slices.Concat(raw.Diagnostics, resolution.Diagnostics),
		}
		if err := normalizer.Normalize(ctx, &finding); err != nil {
			return fmt.Errorf("normalize: %w", err)
		}
		if err := tx.AddFinding(ctx, finding); err != nil {
			return err
		}
		count++
	}
	return tx.CompleteRun(ctx, runID, count)
}

func algoVersion(parser parsers.Parser, normalizer normalizers.Normalizer) string {
	version := fmt.Sprintf("%s@%s", parser.ID(), parser.Version())
	if steps := normalizer.Version(); steps != "" {
		version += "/" + string(steps)
	}
	return version
}

func (w *Worker) settle(ctx context.Context, job queue.Job, run store.Run, procErr error) (Outcome, error) {
	ctx = context.WithoutCancel(ctx)
	if procErr == nil {
		return Outcome{Action: ActionAck}, w.finish(ctx, job, queue.StateDone)
	}
	w.deps.Log.Warn("job failed", "job", job.ID, "attempts", job.Attempts, "error", procErr)
	failErr := w.deps.Store.FailRun(ctx, run, procErr.Error())
	state, outcome := queue.StatePending, Outcome{Action: ActionRetry, Delay: w.cfg.RetryDelay * time.Duration(job.Attempts)}
	if job.Attempts >= w.cfg.MaxAttempts {
		state, outcome = queue.StateDead, Outcome{Action: ActionDead}
	}
	return outcome, errors.Join(failErr, w.finish(ctx, job, state))
}

func (w *Worker) finish(ctx context.Context, job queue.Job, state queue.State) error {
	ok, err := w.deps.Jobs.Finish(ctx, job.ID, w.cfg.ID, state)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("job %s: lease lost before finish", job.ID)
	}
	return nil
}
