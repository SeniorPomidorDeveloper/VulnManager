package adapters

import (
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/parsers"
)

func semgrep() (Adapter, error) {
	return adapterOf(parsers.NewSARIF(), normalizers.SARIF(normalizers.FromLabel))()
}
