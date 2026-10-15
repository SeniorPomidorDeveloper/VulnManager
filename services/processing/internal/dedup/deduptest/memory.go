package deduptest

import (
	"context"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/dedup"
)

type memoryKey struct {
	scope model.ScopeKey
	key   dedup.BlockKey
}

type MemoryIndex struct {
	blocks map[memoryKey][]model.FindingID
}

func NewMemoryIndex() *MemoryIndex {
	return &MemoryIndex{blocks: map[memoryKey][]model.FindingID{}}
}

func (m *MemoryIndex) Add(scope model.Scope, finding model.FindingID, keys []dedup.BlockKey) {
	for _, key := range keys {
		slot := memoryKey{scope: scope.Key(), key: key}
		m.blocks[slot] = append(m.blocks[slot], finding)
	}
}

func (m *MemoryIndex) Lookup(_ context.Context, scope model.Scope, keys []dedup.BlockKey) ([]dedup.Hit, error) {
	var hits []dedup.Hit
	for _, key := range keys {
		for _, finding := range m.blocks[memoryKey{scope: scope.Key(), key: key}] {
			hits = append(hits, dedup.Hit{Finding: finding, Key: key})
		}
	}
	return hits, nil
}
