package adapters

import (
	"vulnmanager/services/normalize/internal/normalizers/blocks"
	"vulnmanager/services/normalize/internal/parsers"
)

func trivy() (Adapter, error) {
	severity := blocks.SeverityByPriority(
		blocks.LabelScale(),
		blocks.CVSSSources("nvd", "ghsa", "redhat", "bitnami"),
		blocks.SeverityFromCVSS, blocks.SeverityFromLabel,
	)
	normalizer := blocks.Compose(blocks.CVSS, blocks.Severity(severity), blocks.VulnID, blocks.Component, blocks.Path("target"))
	return adapterOf(parsers.NewTrivy(), normalizer)()
}
