package adapters

import (
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/parsers"
)

func trivy() (Adapter, error) {
	severity := normalizers.SeverityByPriority(
		normalizers.LabelScale(),
		normalizers.CVSSFrom("nvd", "ghsa", "redhat", "bitnami"),
		normalizers.FromCVSS, normalizers.FromLabel,
	)
	return adapterOf(parsers.NewTrivy(), normalizers.Trivy(severity))()
}
