package adapters

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/parsers"
)

const codeUnknownTool = "unknown_tool"

var ErrIncompleteAdapter = errors.New("adapters: parser and normalizer are required")

type Adapter struct {
	Parser     parsers.Parser
	Normalizer normalizers.Normalizer
}

type Resolution struct {
	Adapter     Adapter
	Diagnostics model.Diagnostics
}

type Registry struct {
	tools    map[model.ToolName]Adapter
	fallback Adapter
}

func New(tools map[model.ToolName]Adapter, fallback Adapter) (*Registry, error) {
	if !fallback.complete() {
		return nil, fmt.Errorf("%w: fallback", ErrIncompleteAdapter)
	}
	for _, tool := range slices.Sorted(maps.Keys(tools)) {
		if !tools[tool].complete() {
			return nil, fmt.Errorf("%w: tool %q", ErrIncompleteAdapter, tool)
		}
	}
	return &Registry{tools: maps.Clone(tools), fallback: fallback}, nil
}

func (a Adapter) complete() bool {
	return a.Parser != nil && a.Normalizer != nil
}

func (r *Registry) Resolve(tool model.ToolName) Resolution {
	if adapter, ok := r.tools[tool]; ok {
		return Resolution{Adapter: adapter}
	}
	return Resolution{
		Adapter:     r.fallback,
		Diagnostics: model.Diagnostics{}.Append(model.DiagLevelWarn, codeUnknownTool, fmt.Sprintf("tool %q has no adapter", tool)),
	}
}
