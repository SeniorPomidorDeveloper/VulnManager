package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/gen/db"
	"vulnmanager/services/processing/internal/dedup"
	"vulnmanager/services/processing/internal/fingerprint"
)

const (
	statusCompleted = "completed"
	backlogWindow   = 7 * 24 * time.Hour
)

var (
	ErrRunNotFound     = errors.New("store: import run not found")
	ErrRunNotCompleted = errors.New("store: import run is not completed")
)

type Run struct {
	ID    model.ImportRunID
	Scope model.Scope
	Tool  model.ToolName
}

type Item struct {
	Finding     model.FindingID
	Fingerprint fingerprint.Fingerprint
}

type Tx interface {
	Run(ctx context.Context, tenant model.TenantID, id model.ImportRunID) (Run, error)
	Begin(ctx context.Context, run Run, algoVersion string) (bool, error)
	Findings(ctx context.Context, run Run) ([]model.Finding, error)
	AddFingerprints(ctx context.Context, run Run, items []Item) error
	LockScope(ctx context.Context, scope model.Scope) error
	Lookup(ctx context.Context, scope model.Scope, keys []dedup.BlockKey) ([]dedup.Hit, error)
	FindingsByID(ctx context.Context, scope model.Scope, ids []model.FindingID) ([]model.Finding, error)
	ClustersOf(ctx context.Context, scope model.Scope, ids []model.FindingID) (map[model.FindingID]dedup.ClusterID, error)
	CreateCluster(ctx context.Context, scope model.Scope, algoVersion string) (dedup.ClusterID, error)
	AddMembers(ctx context.Context, scope model.Scope, algoVersion string, members []Member) error
}

type Backlog struct {
	Runs      int
	OldestAge time.Duration
}

type Store struct {
	pool *pgxpool.Pool
}

type tx struct {
	queries *db.Queries
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Backlog(ctx context.Context) (Backlog, error) {
	row, err := db.New(s.pool).UnprocessedImportRuns(ctx, backlogWindow.Seconds())
	if err != nil {
		return Backlog{}, fmt.Errorf("unprocessed import runs: %w", err)
	}
	return Backlog{Runs: int(row.Runs), OldestAge: time.Duration(row.OldestAgeSeconds * float64(time.Second))}, nil
}

func (s *Store) InTx(ctx context.Context, fn func(Tx) error) error {
	pgxTx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = pgxTx.Rollback(ctx) }()

	queries := db.New(pgxTx)
	if err := queries.UseCustomPlans(ctx); err != nil {
		return fmt.Errorf("custom plans: %w", err)
	}
	if err := fn(tx{queries: queries}); err != nil {
		return err
	}
	if err := pgxTx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (t tx) Run(ctx context.Context, tenant model.TenantID, id model.ImportRunID) (Run, error) {
	runID, err := uuid.Parse(string(id))
	if err != nil {
		return Run{}, fmt.Errorf("import run id: %w", err)
	}
	row, err := t.queries.GetImportRun(ctx, db.GetImportRunParams{TenantID: string(tenant), ID: runID})
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrRunNotFound
	}
	if err != nil {
		return Run{}, fmt.Errorf("get import run: %w", err)
	}
	if row.Status != statusCompleted {
		return Run{}, ErrRunNotCompleted
	}
	scope, err := model.NewScope(tenant, model.ProductID(row.ProductID), model.ContextID(row.ContextID))
	if err != nil {
		return Run{}, fmt.Errorf("scope: %w", err)
	}
	return Run{ID: id, Scope: scope, Tool: model.ToolName(row.ToolName)}, nil
}

func (t tx) Begin(ctx context.Context, run Run, algoVersion string) (bool, error) {
	runID, err := uuid.Parse(string(run.ID))
	if err != nil {
		return false, fmt.Errorf("import run id: %w", err)
	}
	started, err := t.queries.StartProcessingRun(ctx, db.StartProcessingRunParams{
		TenantID:    string(run.Scope.TenantID),
		ImportRunID: runID,
		AlgoVersion: algoVersion,
	})
	if err != nil {
		return false, fmt.Errorf("start processing run: %w", err)
	}
	return started > 0, nil
}

func (t tx) Findings(ctx context.Context, run Run) ([]model.Finding, error) {
	runID, err := uuid.Parse(string(run.ID))
	if err != nil {
		return nil, fmt.Errorf("import run id: %w", err)
	}
	rows, err := t.queries.ListRunFindings(ctx, db.ListRunFindingsParams{
		TenantID: string(run.Scope.TenantID), ImportRunID: runID,
	})
	if err != nil {
		return nil, fmt.Errorf("list run findings: %w", err)
	}
	findings := make([]model.Finding, 0, len(rows))
	for _, row := range rows {
		finding, err := toFinding(run, row)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func (t tx) AddFingerprints(ctx context.Context, run Run, items []Item) error {
	params := make([]db.CopyFindingFingerprintsParams, 0, len(items))
	for _, item := range items {
		findingID, err := uuid.Parse(string(item.Finding))
		if err != nil {
			return fmt.Errorf("finding id: %w", err)
		}
		params = append(params, db.CopyFindingFingerprintsParams{
			TenantID:  string(run.Scope.TenantID),
			FindingID: findingID,
			ScopeKey:  string(run.Scope.Key()),
			Level:     string(item.Fingerprint.Level),
			Strategy:  string(item.Fingerprint.Strategy),
			Version:   int32(item.Fingerprint.Version),
			Value:     string(item.Fingerprint.Value),
		})
	}
	if _, err := t.queries.CopyFindingFingerprints(ctx, params); err != nil {
		return fmt.Errorf("copy finding fingerprints: %w", err)
	}
	return nil
}

func toFinding(run Run, row db.ListRunFindingsRow) (model.Finding, error) {
	kind, err := model.ParseKind(row.Kind)
	if err != nil {
		return model.Finding{}, fmt.Errorf("finding %s kind %q: %w", row.ID, row.Kind, err)
	}
	return model.Finding{
		ID:            model.FindingID(row.ID.String()),
		ImportRunID:   run.ID,
		Scope:         run.Scope,
		ToolFindingID: model.ToolFindingID(row.ToolFindingID),
		Kind:          kind,
		Severity:      severity(row.Severity),
		CWE:           cwes(row.Cwe),
		RuleID:        model.RuleID(row.RuleID.String),
		VulnID:        vulnID(row.VulnSource, row.VulnID),
		Component:     component(row),
		Location:      row.Location,
		Provenance:    model.Provenance{Tool: toolOf(run, row.Tool)},
	}, nil
}

func vulnID(source, value pgtype.Text) model.VulnID {
	if !value.Valid {
		return model.VulnID{}
	}
	return model.VulnID{Source: model.VulnSource(source.String), Value: value.String}
}

func component(row db.ListRunFindingsRow) model.Component {
	if !row.Purl.Valid {
		return model.Component{}
	}
	return model.Component{
		PURL:      model.PURL(row.Purl.String),
		Type:      model.ComponentType(row.ComponentType.String),
		Namespace: row.Namespace.String,
		Name:      row.Name.String,
		Version:   row.Version.String,
	}
}

func severity(name string) model.Severity {
	parsed, err := model.ParseSeverity(name)
	if err != nil {
		return model.SeverityUnknown
	}
	return parsed
}

func cwes(names []string) []model.CWEName {
	result := make([]model.CWEName, 0, len(names))
	for _, name := range names {
		result = append(result, model.CWEName(name))
	}
	return result
}

func toolOf(run Run, recorded string) model.ToolName {
	if recorded != "" {
		return model.ToolName(recorded)
	}
	return run.Tool
}
