package adapters

import (
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/parsers"
)

func generic() (Adapter, error) {
	scale := normalizers.MergeScales(normalizers.LabelScale(), normalizers.SARIFLevelScale())
	severity := normalizers.SeverityByPriority(scale, nil, normalizers.FromLabel)
	return adapterOf(parsers.NewGenericJSON(), normalizers.Generic(severity))()
}
