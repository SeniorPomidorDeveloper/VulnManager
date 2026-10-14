package adapters

import (
	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/parsers"
)

func registered() map[model.ToolName]factory {
	return map[model.ToolName]factory{
		"trivy":   adapterOf(parsers.NewTrivy(), normalizers.NewTrivy),
		"semgrep": adapterOf(parsers.NewSARIF(), normalizers.NewSARIF),
	}
}

func fallback() factory {
	return adapterOf(parsers.NewGenericJSON(), normalizers.NewGeneric)
}
