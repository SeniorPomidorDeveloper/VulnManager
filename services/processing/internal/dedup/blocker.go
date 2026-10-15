package dedup

import (
	"cmp"
	"slices"
)

const (
	byLevelID      BlockerID = "by-level"
	byLevelVersion Version   = 1
)

type ByLevel struct{}

func (ByLevel) ID() BlockerID {
	return byLevelID
}

func (ByLevel) Version() Version {
	return byLevelVersion
}

func (ByLevel) Keys(subject Subject) []BlockKey {
	keys := make([]BlockKey, 0, len(subject.Fingerprints))
	for _, fp := range subject.Fingerprints {
		keys = append(keys, BlockKey{Level: fp.Level, Value: fp.Value})
	}
	return normalized(keys)
}

func compareKeys(a, b BlockKey) int {
	return cmp.Or(cmp.Compare(a.Level, b.Level), cmp.Compare(a.Value, b.Value))
}

func normalized(keys []BlockKey) []BlockKey {
	slices.SortFunc(keys, compareKeys)
	return slices.Compact(keys)
}
