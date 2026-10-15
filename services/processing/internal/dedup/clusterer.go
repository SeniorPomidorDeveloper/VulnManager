package dedup

import (
	"cmp"
	"slices"

	"vulnmanager/modules/model"
)

type (
	ClustererID string
	ClusterID   string
)

const (
	constrainedID      ClustererID = "constrained-union"
	constrainedVersion Version     = 1

	soloConfidence = 1.0
)

type ClusterRef struct {
	Existing ClusterID
	Seed     model.FindingID
}

type Edge struct {
	A, B     model.FindingID
	Decision Decision
}

type Input struct {
	Findings []model.FindingID
	Existing map[model.FindingID]ClusterID
	Edges    []Edge
}

type Assignment struct {
	Finding    model.FindingID
	Cluster    ClusterRef
	Confidence float64
	Reasons    []MatchReason
}

type Result struct {
	Assignments []Assignment
	Review      []Edge
}

type Clusterer interface {
	ID() ClustererID
	Version() Version
	Cluster(input Input) Result
}

type Constrained struct{}

type component struct {
	members []model.FindingID
	anchor  ClusterID
}

type pair struct {
	a, b model.FindingID
}

type state struct {
	parent map[string]string
	groups map[string]*component
	cannot map[model.FindingID][]model.FindingID
}

func (r ClusterRef) IsNew() bool {
	return r.Existing == ""
}

func (Constrained) ID() ClustererID {
	return constrainedID
}

func (Constrained) Version() Version {
	return constrainedVersion
}

func (Constrained) Cluster(input Input) Result {
	edges := normalizedEdges(input.Edges)
	s := newState(input)

	refused := map[pair]struct{}{}
	for _, edge := range edges {
		if edge.Decision.Verdict == VerdictMerge && !s.tryMerge(input, edge) {
			refused[pair{edge.A, edge.B}] = struct{}{}
		}
	}
	return Result{
		Assignments: s.assignments(input, edges),
		Review:      s.review(input, edges, refused),
	}
}

func normalizedEdges(edges []Edge) []Edge {
	result := make([]Edge, 0, len(edges))
	for _, edge := range edges {
		if edge.B < edge.A {
			edge.A, edge.B = edge.B, edge.A
		}
		result = append(result, edge)
	}
	slices.SortFunc(result, func(x, y Edge) int {
		return cmp.Or(
			cmp.Compare(y.Decision.Confidence, x.Decision.Confidence),
			cmp.Compare(x.A, y.A),
			cmp.Compare(x.B, y.B),
		)
	})
	return result
}

func newState(input Input) *state {
	s := &state{
		parent: map[string]string{},
		groups: map[string]*component{},
		cannot: map[model.FindingID][]model.FindingID{},
	}
	for _, finding := range input.Findings {
		s.add(nodeOf(input, finding), finding, "")
	}
	for finding, cluster := range input.Existing {
		s.add(nodeOf(input, finding), finding, cluster)
	}
	for _, edge := range input.Edges {
		if edge.Decision.Verdict == VerdictSeparate {
			s.cannot[edge.A] = append(s.cannot[edge.A], edge.B)
			s.cannot[edge.B] = append(s.cannot[edge.B], edge.A)
		}
	}
	return s
}

func nodeOf(input Input, finding model.FindingID) string {
	if cluster, ok := input.Existing[finding]; ok {
		return "cluster:" + string(cluster)
	}
	return "finding:" + string(finding)
}

func (s *state) add(node string, finding model.FindingID, anchor ClusterID) {
	if _, ok := s.groups[node]; !ok {
		s.parent[node] = node
		s.groups[node] = &component{anchor: anchor}
	}
	s.groups[node].members = append(s.groups[node].members, finding)
}

func (s *state) find(node string) string {
	for s.parent[node] != node {
		s.parent[node] = s.parent[s.parent[node]]
		node = s.parent[node]
	}
	return node
}

func (s *state) known(input Input, finding model.FindingID) bool {
	_, ok := s.parent[nodeOf(input, finding)]
	return ok
}

func (s *state) tryMerge(input Input, edge Edge) bool {
	if !s.known(input, edge.A) || !s.known(input, edge.B) {
		return false
	}
	left, right := s.find(nodeOf(input, edge.A)), s.find(nodeOf(input, edge.B))
	if left == right {
		return true
	}
	if s.groups[left].anchor != "" && s.groups[right].anchor != "" {
		return false
	}
	if s.conflicts(input, left, right) {
		return false
	}
	if s.groups[left].anchor == "" {
		left, right = right, left
	}
	s.parent[right] = left
	s.groups[left].members = append(s.groups[left].members, s.groups[right].members...)
	delete(s.groups, right)
	return true
}

func (s *state) conflicts(input Input, left, right string) bool {
	small, large := left, right
	if len(s.groups[small].members) > len(s.groups[large].members) {
		small, large = large, small
	}
	for _, member := range s.groups[small].members {
		for _, other := range s.cannot[member] {
			if s.known(input, other) && s.find(nodeOf(input, other)) == large {
				return true
			}
		}
	}
	return false
}

func (s *state) refOf(input Input, finding model.FindingID) ClusterRef {
	root := s.find(nodeOf(input, finding))
	if anchor := s.groups[root].anchor; anchor != "" {
		return ClusterRef{Existing: anchor}
	}
	return ClusterRef{Seed: slices.Min(s.groups[root].members)}
}

func (s *state) assignments(input Input, edges []Edge) []Assignment {
	best := s.strongestEdges(input, edges)
	result := make([]Assignment, 0, len(input.Findings))
	for _, finding := range input.Findings {
		assignment := Assignment{Finding: finding, Cluster: s.refOf(input, finding), Confidence: soloConfidence}
		if edge, ok := best[finding]; ok {
			assignment.Confidence, assignment.Reasons = edge.Decision.Confidence, edge.Decision.Reasons
		}
		result = append(result, assignment)
	}
	slices.SortFunc(result, func(x, y Assignment) int { return cmp.Compare(x.Finding, y.Finding) })
	return result
}

func (s *state) strongestEdges(input Input, edges []Edge) map[model.FindingID]Edge {
	best := map[model.FindingID]Edge{}
	for _, edge := range edges {
		if edge.Decision.Verdict != VerdictMerge || !s.together(input, edge) {
			continue
		}
		for _, end := range []model.FindingID{edge.A, edge.B} {
			if _, set := best[end]; !set {
				best[end] = edge
			}
		}
	}
	return best
}

func (s *state) together(input Input, edge Edge) bool {
	return s.known(input, edge.A) && s.known(input, edge.B) &&
		s.find(nodeOf(input, edge.A)) == s.find(nodeOf(input, edge.B))
}

func (s *state) review(input Input, edges []Edge, refused map[pair]struct{}) []Edge {
	var review []Edge
	for _, edge := range edges {
		_, blocked := refused[pair{edge.A, edge.B}]
		if (edge.Decision.Verdict == VerdictReview || blocked) && !s.together(input, edge) {
			review = append(review, edge)
		}
	}
	return review
}
