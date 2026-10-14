package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/gen/db"
)

var ErrAlreadyCompleted = errors.New("store: report is already processed")

type Store struct {
	pool *pgxpool.Pool
}

type Tx struct {
	queries    *db.Queries
	components map[string]uuid.UUID
}

type Run struct {
	Scope  model.Scope
	Tool   model.ToolName
	ScanID model.ScanID
	RawKey string
	SHA256 string
}

type provenanceRecord struct {
	Tool                   string `json:"tool"`
	ToolVersion            string `json:"tool_version"`
	ScanID                 string `json:"scan_id"`
	ContextSnapshotVersion string `json:"context_snapshot_version"`
}

type diagnosticRecord struct {
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type statsRecord struct {
	Findings int    `json:"findings"`
	Error    string `json:"error,omitempty"`
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) InTx(ctx context.Context, fn func(*Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	queries := db.New(tx)
	if err := fn(&Tx{queries: queries, components: map[string]uuid.UUID{}}); err != nil {
		return err
	}
	return commit(ctx, tx)
}

func commit(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (s *Store) FailRun(ctx context.Context, run Run, reason string) error {
	stats, err := json.Marshal(statsRecord{Error: reason})
	if err != nil {
		return fmt.Errorf("encode stats: %w", err)
	}
	return s.InTx(ctx, func(tx *Tx) error {
		return tx.queries.FailImportRun(ctx, db.FailImportRunParams{
			TenantID:  string(run.Scope.TenantID),
			ScopeKey:  string(run.Scope.Key()),
			ProductID: string(run.Scope.ProductID),
			ContextID: string(run.Scope.ContextID),
			ToolName:  string(run.Tool),
			ScanID:    string(run.ScanID),
			RawKey:    run.RawKey,
			RawSha256: run.SHA256,
			Stats:     stats,
		})
	})
}

func (t *Tx) StartRun(ctx context.Context, run Run) (model.ImportRunID, error) {
	id, err := t.queries.UpsertImportRun(ctx, db.UpsertImportRunParams{
		TenantID:  string(run.Scope.TenantID),
		ScopeKey:  string(run.Scope.Key()),
		ProductID: string(run.Scope.ProductID),
		ContextID: string(run.Scope.ContextID),
		ToolName:  string(run.Tool),
		ScanID:    string(run.ScanID),
		RawKey:    run.RawKey,
		RawSha256: run.SHA256,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrAlreadyCompleted
	}
	if err != nil {
		return "", fmt.Errorf("start import run: %w", err)
	}
	return model.ImportRunID(id.String()), nil
}

func vulnColumns(id model.VulnID) (source, value pgtype.Text) {
	valid := !id.IsZero()
	return pgtype.Text{String: string(id.Source), Valid: valid}, pgtype.Text{String: id.Value, Valid: valid}
}

func (t *Tx) componentID(ctx context.Context, tenant model.TenantID, component model.Component) (pgtype.UUID, error) {
	if component.IsZero() {
		return pgtype.UUID{}, nil
	}
	key := string(tenant) + "|" + string(component.PURL)
	if id, cached := t.components[key]; cached {
		return pgtype.UUID{Bytes: id, Valid: true}, nil
	}
	id, err := t.queries.UpsertComponent(ctx, db.UpsertComponentParams{
		TenantID:  string(tenant),
		Purl:      string(component.PURL),
		Type:      string(component.Type),
		Namespace: component.Namespace,
		Name:      component.Name,
		Version:   component.Version,
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("upsert component: %w", err)
	}
	t.components[key] = id
	return pgtype.UUID{Bytes: id, Valid: true}, nil
}

func (t *Tx) AddFinding(ctx context.Context, finding model.Finding) error {
	runID, err := uuid.Parse(string(finding.ImportRunID))
	if err != nil {
		return fmt.Errorf("import run id: %w", err)
	}
	provenance, err := provenanceJSON(finding.Provenance)
	if err != nil {
		return err
	}
	diagnostics, err := diagnosticsJSON(finding.Diagnostics)
	if err != nil {
		return err
	}
	vulnSource, vulnValue := vulnColumns(finding.VulnID)
	componentID, err := t.componentID(ctx, finding.Scope.TenantID, finding.Component)
	if err != nil {
		return err
	}
	findingID, err := t.queries.InsertFinding(ctx, db.InsertFindingParams{
		TenantID:      string(finding.Scope.TenantID),
		ImportRunID:   runID,
		ScopeKey:      string(finding.Scope.Key()),
		ProductID:     string(finding.Scope.ProductID),
		ContextID:     string(finding.Scope.ContextID),
		ToolFindingID: string(finding.ToolFindingID),
		Kind:          finding.Kind.String(),
		Title:         finding.Title,
		Description:   finding.Description,
		SeverityRaw:   string(finding.SeverityRaw),
		Severity:      finding.Severity.String(),
		VulnSource:    vulnSource,
		VulnID:        vulnValue,
		ComponentID:   componentID,
		Location:      finding.Location,
		Raw:           finding.Raw,
		Provenance:    provenance,
		AlgoVersion:   finding.AlgoVersion,
		Diagnostics:   diagnostics,
		DetectedAt:    finding.DetectedAt,
	})
	if err != nil {
		return fmt.Errorf("insert finding: %w", err)
	}
	return t.addCVSS(ctx, finding.Scope.TenantID, findingID, finding.CVSS)
}

func (t *Tx) addCVSS(ctx context.Context, tenant model.TenantID, findingID uuid.UUID, scores []model.CVSSScore) error {
	for _, score := range scores {
		err := t.queries.InsertFindingCVSS(ctx, db.InsertFindingCVSSParams{
			TenantID:  string(tenant),
			FindingID: findingID,
			Source:    string(score.Source),
			Version:   string(score.Version),
			Vector:    string(score.Vector),
			Score:     float64(score.BaseScore),
		})
		if err != nil {
			return fmt.Errorf("insert finding cvss: %w", err)
		}
	}
	return nil
}

func (t *Tx) CompleteRun(ctx context.Context, id model.ImportRunID, findings int) error {
	runID, err := uuid.Parse(string(id))
	if err != nil {
		return fmt.Errorf("import run id: %w", err)
	}
	stats, err := json.Marshal(statsRecord{Findings: findings})
	if err != nil {
		return fmt.Errorf("encode stats: %w", err)
	}
	if err := t.queries.CompleteImportRun(ctx, db.CompleteImportRunParams{ID: runID, Stats: stats}); err != nil {
		return fmt.Errorf("complete import run: %w", err)
	}
	return nil
}

func provenanceJSON(provenance model.Provenance) ([]byte, error) {
	encoded, err := json.Marshal(provenanceRecord{
		Tool:                   string(provenance.Tool),
		ToolVersion:            string(provenance.ToolVersion),
		ScanID:                 string(provenance.ScanID),
		ContextSnapshotVersion: provenance.ContextSnapshotVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("encode provenance: %w", err)
	}
	return encoded, nil
}

func diagnosticsJSON(diagnostics model.Diagnostics) ([]byte, error) {
	records := make([]diagnosticRecord, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		records = append(records, diagnosticRecord{
			Level:   string(diagnostic.Level),
			Code:    diagnostic.Code,
			Message: diagnostic.Message,
		})
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		return nil, fmt.Errorf("encode diagnostics: %w", err)
	}
	return encoded, nil
}
