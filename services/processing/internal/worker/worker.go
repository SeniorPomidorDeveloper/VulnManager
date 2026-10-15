package worker

import (
	"context"
	"errors"
	"fmt"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/fingerprint"
	"vulnmanager/services/processing/internal/store"
)

var ErrInvalidConfig = errors.New("worker: invalid config")

type Result struct {
	Tool            model.ToolName
	Already         bool
	Findings        int
	Unfingerprinted int
	Skipped         map[fingerprint.Level]int
}

type Store interface {
	InTx(ctx context.Context, fn func(store.Tx) error) error
}

type Worker struct {
	store    Store
	registry *fingerprint.Registry
}

func New(s Store, registry *fingerprint.Registry) (*Worker, error) {
	if s == nil || registry == nil {
		return nil, ErrInvalidConfig
	}
	return &Worker{store: s, registry: registry}, nil
}

func (w *Worker) Handle(ctx context.Context, tenant model.TenantID, id model.ImportRunID) (Result, error) {
	var result Result
	err := w.store.InTx(ctx, func(tx store.Tx) error {
		run, err := tx.Run(ctx, tenant, id)
		if err != nil {
			return fmt.Errorf("run: %w", err)
		}
		set := w.registry.For(run.Tool)
		fresh, err := tx.Begin(ctx, run, set.AlgoVersion())
		if err != nil {
			return fmt.Errorf("begin: %w", err)
		}
		result = Result{Tool: run.Tool, Already: !fresh, Skipped: map[fingerprint.Level]int{}}
		if !fresh {
			return nil
		}
		findings, err := tx.Findings(ctx, run)
		if err != nil {
			return fmt.Errorf("findings: %w", err)
		}
		items := compute(set, findings, &result)
		if err := tx.AddFingerprints(ctx, run, items); err != nil {
			return fmt.Errorf("add fingerprints: %w", err)
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func compute(set fingerprint.Set, findings []model.Finding, result *Result) []store.Item {
	result.Findings = len(findings)
	var items []store.Item
	for _, finding := range findings {
		computed, _ := set.Compute(finding)
		if len(computed) == 0 {
			result.Unfingerprinted++
		}
		have := make(map[fingerprint.Level]struct{}, len(computed))
		for _, fp := range computed {
			have[fp.Level] = struct{}{}
			items = append(items, store.Item{Finding: finding.ID, Fingerprint: fp})
		}
		for _, level := range set.Levels() {
			if _, ok := have[level]; !ok {
				result.Skipped[level]++
			}
		}
	}
	return items
}
