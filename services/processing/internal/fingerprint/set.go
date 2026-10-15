package fingerprint

import (
	"errors"
	"fmt"
	"strings"

	"vulnmanager/modules/model"
)

const (
	codeSkipped       = "fingerprint_level_skipped"
	codeNoFingerprint = "no_fingerprint"
)

var ErrDuplicateStrategy = errors.New("fingerprint: duplicate strategy level")

type Set struct {
	strategies []Strategy
}

func NewSet(strategies ...Strategy) (Set, error) {
	seen := make(map[Level]struct{}, len(strategies))
	for _, strategy := range strategies {
		if _, dup := seen[strategy.Level()]; dup {
			return Set{}, fmt.Errorf("%w: %s", ErrDuplicateStrategy, strategy.Level())
		}
		seen[strategy.Level()] = struct{}{}
	}
	return Set{strategies: append([]Strategy(nil), strategies...)}, nil
}

func (s Set) Levels() []Level {
	levels := make([]Level, 0, len(s.strategies))
	for _, strategy := range s.strategies {
		levels = append(levels, strategy.Level())
	}
	return levels
}

func (s Set) AlgoVersion() string {
	parts := make([]string, 0, len(s.strategies))
	for _, strategy := range s.strategies {
		parts = append(parts, fmt.Sprintf("%s@%d", strategy.ID(), strategy.Version()))
	}
	return strings.Join(parts, "+")
}

func (s Set) Compute(finding model.Finding) ([]Fingerprint, model.Diagnostics) {
	var (
		result      []Fingerprint
		diagnostics model.Diagnostics
	)
	for _, strategy := range s.strategies {
		fingerprint, ok := strategy.Fingerprint(finding)
		if !ok {
			diagnostics = diagnostics.Append(
				model.DiagLevelInfo, codeSkipped, string(strategy.Level())+" "+string(strategy.ID()),
			)
			continue
		}
		result = append(result, fingerprint)
	}
	if len(result) == 0 {
		diagnostics = diagnostics.Append(model.DiagLevelWarn, codeNoFingerprint, "no fingerprint level is computable")
	}
	return result, diagnostics
}
