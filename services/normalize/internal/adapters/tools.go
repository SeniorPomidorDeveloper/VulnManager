package adapters

import "vulnmanager/modules/model"

func registered() map[model.ToolName]factory {
	return map[model.ToolName]factory{
		"trivy":   trivy,
		"semgrep": semgrep,
	}
}

func fallback() factory {
	return generic
}
