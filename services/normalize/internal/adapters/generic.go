package adapters

import (
	"vulnmanager/services/normalize/internal/normalizers/blocks"
	"vulnmanager/services/normalize/internal/parsers"
)

func generic() (Adapter, error) {
	scale := blocks.MergeScales(blocks.LabelScale(), blocks.SARIFLevelScale())
	severity := blocks.SeverityByPriority(scale, nil, blocks.SeverityFromLabel)
	normalizer := blocks.Compose(blocks.Severity(severity), blocks.VulnID, blocks.Path("uri", "target"))
	return adapterOf(parsers.NewGenericJSON(), normalizer)()
}
