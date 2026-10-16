package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/gen/db"
	"vulnmanager/services/processing/internal/dedup"
	"vulnmanager/services/processing/internal/fingerprint"
)

const lookupChunk = 5000

type Member struct {
	Finding    model.FindingID
	Cluster    dedup.ClusterID
	Confidence float64
	Reasons    []dedup.MatchReason
}

type reasonRecord struct {
	Feature string `json:"feature"`
	Signal  string `json:"signal"`
	Points  int    `json:"points"`
}

func (t tx) LockScope(ctx context.Context, scope model.Scope) error {
	if err := t.queries.LockScope(ctx, string(scope.Key())); err != nil {
		return fmt.Errorf("lock scope: %w", err)
	}
	return nil
}

func (t tx) Lookup(ctx context.Context, scope model.Scope, keys []dedup.BlockKey) ([]dedup.Hit, error) {
	hits := make([]dedup.Hit, 0, len(keys))
	for start := 0; start < len(keys); start += lookupChunk {
		chunk := keys[start:min(start+lookupChunk, len(keys))]
		levels := make([]string, 0, len(chunk))
		values := make([]string, 0, len(chunk))
		for _, key := range chunk {
			levels = append(levels, string(key.Level))
			values = append(values, string(key.Value))
		}
		rows, err := t.queries.LookupFingerprints(ctx, db.LookupFingerprintsParams{
			TenantID: string(scope.TenantID), ScopeKey: string(scope.Key()), Levels: levels, Values: values,
		})
		if err != nil {
			return nil, fmt.Errorf("lookup fingerprints: %w", err)
		}
		for _, row := range rows {
			key := dedup.BlockKey{Level: fingerprint.Level(row.Level), Value: fingerprint.Value(row.Value)}
			hits = append(hits, dedup.Hit{Finding: model.FindingID(row.FindingID.String()), Key: key})
		}
	}
	return hits, nil
}

func (t tx) FindingsByID(ctx context.Context, scope model.Scope, ids []model.FindingID) ([]model.Finding, error) {
	parsed, err := parseIDs(ids)
	if err != nil {
		return nil, err
	}
	rows, err := t.queries.ListFindingsByID(ctx, db.ListFindingsByIDParams{TenantID: string(scope.TenantID), Ids: parsed})
	if err != nil {
		return nil, fmt.Errorf("list findings by id: %w", err)
	}
	findings := make([]model.Finding, 0, len(rows))
	for _, row := range rows {
		finding, err := toFinding(Run{Scope: scope}, db.ListRunFindingsRow(row))
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func (t tx) ClustersOf(
	ctx context.Context, scope model.Scope, ids []model.FindingID,
) (map[model.FindingID]dedup.ClusterID, error) {
	parsed, err := parseIDs(ids)
	if err != nil {
		return nil, err
	}
	rows, err := t.queries.ClusterOfFindings(ctx, db.ClusterOfFindingsParams{TenantID: string(scope.TenantID), Ids: parsed})
	if err != nil {
		return nil, fmt.Errorf("cluster of findings: %w", err)
	}
	clusters := make(map[model.FindingID]dedup.ClusterID, len(rows))
	for _, row := range rows {
		clusters[model.FindingID(row.FindingID.String())] = dedup.ClusterID(row.ClusterID.String())
	}
	return clusters, nil
}

func (t tx) CreateCluster(ctx context.Context, scope model.Scope, algoVersion string) (dedup.ClusterID, error) {
	id, err := t.queries.InsertCluster(ctx, db.InsertClusterParams{
		TenantID: string(scope.TenantID), ScopeKey: string(scope.Key()), AlgoVersion: algoVersion,
	})
	if err != nil {
		return "", fmt.Errorf("insert cluster: %w", err)
	}
	return dedup.ClusterID(id.String()), nil
}

func (t tx) AddMembers(ctx context.Context, scope model.Scope, algoVersion string, members []Member) error {
	params := make([]db.CopyClusterMembersParams, 0, len(members))
	for _, member := range members {
		clusterID, err := uuid.Parse(string(member.Cluster))
		if err != nil {
			return fmt.Errorf("cluster id: %w", err)
		}
		findingID, err := uuid.Parse(string(member.Finding))
		if err != nil {
			return fmt.Errorf("finding id: %w", err)
		}
		reasons, err := json.Marshal(reasonRecords(member.Reasons))
		if err != nil {
			return fmt.Errorf("encode reasons: %w", err)
		}
		params = append(params, db.CopyClusterMembersParams{
			TenantID: string(scope.TenantID), ClusterID: clusterID, FindingID: findingID,
			Confidence: member.Confidence, Reasons: reasons, AlgoVersion: algoVersion,
		})
	}
	if _, err := t.queries.CopyClusterMembers(ctx, params); err != nil {
		return fmt.Errorf("copy cluster members: %w", err)
	}
	return nil
}

func parseIDs(ids []model.FindingID) ([]uuid.UUID, error) {
	parsed := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		value, err := uuid.Parse(string(id))
		if err != nil {
			return nil, fmt.Errorf("finding id: %w", err)
		}
		parsed = append(parsed, value)
	}
	return parsed, nil
}

func reasonRecords(reasons []dedup.MatchReason) []reasonRecord {
	records := make([]reasonRecord, 0, len(reasons))
	for _, reason := range reasons {
		records = append(records, reasonRecord{
			Feature: string(reason.Feature), Signal: string(reason.Signal), Points: int(reason.Points),
		})
	}
	return records
}
