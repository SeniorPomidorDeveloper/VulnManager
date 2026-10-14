package adapters

import (
	"errors"
	"fmt"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/parsers"
)

type factory func() (Adapter, error)

func adapterOf(parser parsers.Parser, build func() (normalizers.Normalizer, error)) factory {
	return func() (Adapter, error) {
		normalizer, err := build()
		if err != nil {
			return Adapter{}, err
		}
		return Adapter{Parser: parser, Normalizer: normalizer}, nil
	}
}

func Builtin() (*Registry, error) {
	entries := registered()
	tools := make(map[model.ToolName]Adapter, len(entries))
	var errs []error
	for tool, build := range entries {
		adapter, err := build()
		if err != nil {
			errs = append(errs, fmt.Errorf("tool %q: %w", tool, err))
			continue
		}
		tools[tool] = adapter
	}
	fallbackAdapter, err := fallback()()
	if err != nil {
		errs = append(errs, fmt.Errorf("fallback: %w", err))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return New(tools, fallbackAdapter)
}
