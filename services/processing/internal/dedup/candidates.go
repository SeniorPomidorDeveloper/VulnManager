package dedup

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"

	"vulnmanager/modules/model"
)

func Find(ctx context.Context, blocker Blocker, index Index, subject Subject) ([]Candidate, error) {
	if subject.Scope.TenantID.IsEmpty() {
		return nil, model.ErrEmptyTenant
	}
	keys := blocker.Keys(subject)
	if len(keys) == 0 {
		return nil, nil
	}
	hits, err := index.Lookup(ctx, subject.Scope, keys)
	if err != nil {
		return nil, fmt.Errorf("lookup: %w", err)
	}
	return group(hits, subject.Finding), nil
}

func FindMany(ctx context.Context, blocker Blocker, index Index, scope model.Scope, subjects []Subject) (map[model.FindingID][]Candidate, error) {
	if scope.TenantID.IsEmpty() {
		return nil, model.ErrEmptyTenant
	}
	keysOf := make(map[model.FindingID][]BlockKey, len(subjects))
	unique := map[BlockKey]struct{}{}
	for _, subject := range subjects {
		keys := blocker.Keys(subject)
		keysOf[subject.Finding] = keys
		for _, key := range keys {
			unique[key] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return map[model.FindingID][]Candidate{}, nil
	}
	hits, err := index.Lookup(ctx, scope, slices.SortedFunc(maps.Keys(unique), compareKeys))
	if err != nil {
		return nil, fmt.Errorf("lookup: %w", err)
	}
	byKey := make(map[BlockKey][]Hit, len(unique))
	for _, hit := range hits {
		byKey[hit.Key] = append(byKey[hit.Key], hit)
	}
	found := make(map[model.FindingID][]Candidate, len(subjects))
	for _, subject := range subjects {
		var own []Hit
		for _, key := range keysOf[subject.Finding] {
			own = append(own, byKey[key]...)
		}
		found[subject.Finding] = group(own, subject.Finding)
	}
	return found, nil
}

func group(hits []Hit, self model.FindingID) []Candidate {
	byFinding := map[model.FindingID][]BlockKey{}
	for _, hit := range hits {
		if hit.Finding != self {
			byFinding[hit.Finding] = append(byFinding[hit.Finding], hit.Key)
		}
	}
	candidates := make([]Candidate, 0, len(byFinding))
	for finding, keys := range byFinding {
		candidates = append(candidates, Candidate{Finding: finding, Keys: normalized(keys)})
	}
	slices.SortFunc(candidates, func(a, b Candidate) int { return cmp.Compare(a.Finding, b.Finding) })
	return candidates
}
