package worker

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/dedup"
	"vulnmanager/services/processing/internal/fingerprint"
	"vulnmanager/services/processing/internal/store"
)

type Dedup struct {
	Blocker   dedup.Blocker
	Scorer    dedup.Scorer
	Clusterer dedup.Clusterer
}

type ClusterStats struct {
	AlgoVersion string
	Candidates  []int
	Verdicts    map[dedup.Verdict]int
	Confidences []float64
	Created     int
	Joined      int
	Review      int
	Unclustered int
}

type pair struct {
	a, b model.FindingID
}

func (d Dedup) valid() bool {
	return d.Blocker != nil && d.Scorer != nil && d.Clusterer != nil
}

func (d Dedup) AlgoVersion() string {
	return fmt.Sprintf("%s@%d+%s@%d+%s@%d",
		d.Blocker.ID(), d.Blocker.Version(), d.Scorer.ID(), d.Scorer.Version(), d.Clusterer.ID(), d.Clusterer.Version())
}

func (w *Worker) cluster(ctx context.Context, tx store.Tx, run store.Run, findings []model.Finding, items []store.Item) (ClusterStats, error) {
	stats := ClusterStats{AlgoVersion: w.deduper.AlgoVersion(), Verdicts: map[dedup.Verdict]int{}}
	fingerprints := groupFingerprints(items)
	records := make(map[model.FindingID]dedup.Record, len(findings))
	for _, finding := range findings {
		records[finding.ID] = dedup.RecordOf(finding)
	}

	subjects, found, foreign, err := w.candidates(ctx, tx, run, findings, fingerprints, records)
	if err != nil {
		return stats, err
	}
	stats.Candidates = candidateCounts(subjects, found)
	loaded, err := tx.FindingsByID(ctx, run.Scope, foreign)
	if err != nil {
		return stats, fmt.Errorf("foreign findings: %w", err)
	}
	for _, finding := range loaded {
		records[finding.ID] = dedup.RecordOf(finding)
	}
	existing, err := tx.ClustersOf(ctx, run.Scope, foreign)
	if err != nil {
		return stats, fmt.Errorf("clusters of candidates: %w", err)
	}

	edges := w.score(subjects, found, records, existing, &stats)
	result := w.deduper.Clusterer.Cluster(dedup.Input{Findings: subjects, Existing: existing, Edges: edges})
	stats.Review = len(result.Review)
	return stats, w.persist(ctx, tx, run, result, &stats)
}

func (w *Worker) candidates(
	ctx context.Context, tx store.Tx, run store.Run, findings []model.Finding,
	fingerprints map[model.FindingID][]fingerprint.Fingerprint, records map[model.FindingID]dedup.Record,
) (subjects []model.FindingID, found map[model.FindingID][]dedup.Candidate, foreign []model.FindingID, err error) {
	found = map[model.FindingID][]dedup.Candidate{}
	foreignSet := map[model.FindingID]struct{}{}
	for _, finding := range findings {
		if len(fingerprints[finding.ID]) == 0 {
			continue
		}
		subject := dedup.Subject{Finding: finding.ID, Scope: run.Scope, Fingerprints: fingerprints[finding.ID]}
		candidates, err := dedup.Find(ctx, w.deduper.Blocker, tx, subject)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("candidates of %s: %w", finding.ID, err)
		}
		subjects = append(subjects, finding.ID)
		found[finding.ID] = candidates
		for _, candidate := range candidates {
			if _, own := records[candidate.Finding]; !own {
				foreignSet[candidate.Finding] = struct{}{}
			}
		}
	}
	foreign = slices.Sorted(maps.Keys(foreignSet))
	return subjects, found, foreign, nil
}

func (w *Worker) score(
	subjects []model.FindingID, found map[model.FindingID][]dedup.Candidate,
	records map[model.FindingID]dedup.Record, existing map[model.FindingID]dedup.ClusterID, stats *ClusterStats,
) []dedup.Edge {
	var edges []dedup.Edge
	seen := map[pair]struct{}{}
	current := make(map[model.FindingID]struct{}, len(subjects))
	for _, subject := range subjects {
		current[subject] = struct{}{}
	}
	for _, subject := range subjects {
		for _, candidate := range found[subject] {
			_, inRun := current[candidate.Finding]
			_, clustered := existing[candidate.Finding]
			if !inRun && !clustered {
				stats.Unclustered++
				continue
			}
			key := pair{min(subject, candidate.Finding), max(subject, candidate.Finding)}
			if _, done := seen[key]; done {
				continue
			}
			seen[key] = struct{}{}
			decision := w.deduper.Scorer.Score(records[key.a], records[key.b])
			stats.Verdicts[decision.Verdict]++
			edges = append(edges, dedup.Edge{A: key.a, B: key.b, Decision: decision})
		}
	}
	return edges
}

func (w *Worker) persist(ctx context.Context, tx store.Tx, run store.Run, result dedup.Result, stats *ClusterStats) error {
	algo := w.deduper.AlgoVersion()
	created := map[model.FindingID]dedup.ClusterID{}
	for _, assignment := range result.Assignments {
		if !assignment.Cluster.IsNew() {
			continue
		}
		if _, done := created[assignment.Cluster.Seed]; done {
			continue
		}
		id, err := tx.CreateCluster(ctx, run.Scope, algo)
		if err != nil {
			return fmt.Errorf("create cluster: %w", err)
		}
		created[assignment.Cluster.Seed] = id
		stats.Created++
	}
	members := make([]store.Member, 0, len(result.Assignments))
	for _, assignment := range result.Assignments {
		cluster := assignment.Cluster.Existing
		if assignment.Cluster.IsNew() {
			cluster = created[assignment.Cluster.Seed]
		} else {
			stats.Joined++
		}
		stats.Confidences = append(stats.Confidences, assignment.Confidence)
		members = append(members, store.Member{
			Finding: assignment.Finding, Cluster: cluster, Confidence: assignment.Confidence, Reasons: assignment.Reasons,
		})
	}
	if err := tx.AddMembers(ctx, run.Scope, algo, members); err != nil {
		return fmt.Errorf("add cluster members: %w", err)
	}
	return nil
}

func candidateCounts(subjects []model.FindingID, found map[model.FindingID][]dedup.Candidate) []int {
	counts := make([]int, 0, len(subjects))
	for _, subject := range subjects {
		counts = append(counts, len(found[subject]))
	}
	return counts
}

func groupFingerprints(items []store.Item) map[model.FindingID][]fingerprint.Fingerprint {
	grouped := map[model.FindingID][]fingerprint.Fingerprint{}
	for _, item := range items {
		grouped[item.Finding] = append(grouped[item.Finding], item.Fingerprint)
	}
	return grouped
}
