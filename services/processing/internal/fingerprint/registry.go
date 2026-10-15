package fingerprint

import (
	"errors"
	"fmt"

	"vulnmanager/modules/model"
)

var ErrDuplicateTool = errors.New("fingerprint: tool already registered")

type Registry struct {
	fallback Set
	byTool   map[model.ToolName]Set
}

func NewRegistry(fallback Set) *Registry {
	return &Registry{fallback: fallback, byTool: map[model.ToolName]Set{}}
}

func (r *Registry) Register(tool model.ToolName, set Set) error {
	if _, dup := r.byTool[tool]; dup {
		return fmt.Errorf("%w: %s", ErrDuplicateTool, tool)
	}
	r.byTool[tool] = set
	return nil
}

func (r *Registry) For(tool model.ToolName) Set {
	if set, ok := r.byTool[tool]; ok {
		return set
	}
	return r.fallback
}

func (r *Registry) Has(tool model.ToolName) bool {
	_, ok := r.byTool[tool]
	return ok
}
