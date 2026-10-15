package dedup

import (
	"context"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/fingerprint"
)

type (
	BlockerID string
	Version   int
)

type BlockKey struct {
	Level fingerprint.Level
	Value fingerprint.Value
}

type Subject struct {
	Finding      model.FindingID
	Scope        model.Scope
	Fingerprints []fingerprint.Fingerprint
}

type Hit struct {
	Finding model.FindingID
	Key     BlockKey
}

type Candidate struct {
	Finding model.FindingID
	Keys    []BlockKey
}

type Blocker interface {
	ID() BlockerID
	Version() Version
	Keys(subject Subject) []BlockKey
}

type Index interface {
	Lookup(ctx context.Context, scope model.Scope, keys []BlockKey) ([]Hit, error)
}
