package normalizers

import (
	"fmt"

	"vulnmanager/modules/model"
)

type ProfileSpec struct {
	Default []NormalizerID
	ByTool  map[model.ToolName][]NormalizerID
}

type Profiles struct {
	fallback Chain
	byTool   map[model.ToolName]Chain
}

func (r *Registry) Profiles(spec ProfileSpec) (Profiles, error) {
	fallback, err := r.Chain(spec.Default...)
	if err != nil {
		return Profiles{}, fmt.Errorf("default profile: %w", err)
	}
	byTool := make(map[model.ToolName]Chain, len(spec.ByTool))
	for tool, ids := range spec.ByTool {
		chain, err := r.Chain(ids...)
		if err != nil {
			return Profiles{}, fmt.Errorf("profile %q: %w", tool, err)
		}
		byTool[tool] = chain
	}
	return Profiles{fallback: fallback, byTool: byTool}, nil
}

func (p Profiles) For(tool model.ToolName) Chain {
	if chain, ok := p.byTool[tool]; ok {
		return chain
	}
	return p.fallback
}
