package parsers

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

const SniffThreshold SniffScore = 0.5

var ErrDuplicateParser = errors.New("parsers: duplicate parser id")

type Registry struct {
	parsers  map[ParserID]Parser
	fallback Parser
}

func NewRegistry(fallback Parser) *Registry {
	return &Registry{parsers: map[ParserID]Parser{}, fallback: fallback}
}

func (r *Registry) Register(p Parser) error {
	if _, exists := r.parsers[p.ID()]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateParser, p.ID())
	}
	r.parsers[p.ID()] = p
	return nil
}

func (r *Registry) Get(id ParserID) (Parser, bool) {
	p, ok := r.parsers[id]
	return p, ok
}

func (r *Registry) Detect(head []byte) Parser {
	best, bestScore := r.fallback, SniffThreshold
	for _, id := range slices.Sorted(maps.Keys(r.parsers)) {
		if score := r.parsers[id].Sniff(head); score > bestScore {
			best, bestScore = r.parsers[id], score
		}
	}
	return best
}
