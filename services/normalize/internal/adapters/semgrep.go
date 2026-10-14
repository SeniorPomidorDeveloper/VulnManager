package adapters

import (
	"vulnmanager/services/normalize/internal/normalizers/blocks"
	"vulnmanager/services/normalize/internal/parsers"
)

func semgrep() (Adapter, error) {
	severity := blocks.SeverityByPriority(blocks.SARIFLevelScale(), nil, blocks.SeverityFromScore, blocks.SeverityFromLabel)
	normalizer := blocks.Compose(blocks.Severity(severity), blocks.Path("uri"))
	return adapterOf(parsers.NewSARIF(), normalizer)()
}
