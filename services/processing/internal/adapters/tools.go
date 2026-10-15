package adapters

import (
	"fmt"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/fingerprint"
)

func strategies() map[model.ToolName][]fingerprint.Strategy {
	return map[model.ToolName][]fingerprint.Strategy{
		"trivy":   {fingerprint.ToolUID{}, fingerprint.Identity{}},
		"semgrep": {fingerprint.ToolUID{}, fingerprint.Structural{}},
	}
}

func fallback() []fingerprint.Strategy {
	return []fingerprint.Strategy{fingerprint.ToolUID{}}
}

func Builtin() (*fingerprint.Registry, error) {
	base, err := fingerprint.NewSet(fallback()...)
	if err != nil {
		return nil, fmt.Errorf("fallback set: %w", err)
	}
	registry := fingerprint.NewRegistry(base)
	for tool, list := range strategies() {
		set, err := fingerprint.NewSet(list...)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tool, err)
		}
		if err := registry.Register(tool, set); err != nil {
			return nil, err
		}
	}
	return registry, nil
}
