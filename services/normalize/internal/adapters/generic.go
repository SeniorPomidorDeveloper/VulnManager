package adapters

import (
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/parsers"
)

func generic() (Adapter, error) {
	return adapterOf(parsers.NewGenericJSON(), normalizers.Generic(normalizers.FromLabel))()
}
