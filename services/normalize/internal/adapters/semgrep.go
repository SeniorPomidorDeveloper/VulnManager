package adapters

import (
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/parsers"
)

func semgrep() (Adapter, error) {
	severity := normalizers.SeverityByPriority(normalizers.SARIFLevelScale(), nil, normalizers.FromLabel)
	return adapterOf(parsers.NewSARIF(), normalizers.SARIF(severity))()
}
