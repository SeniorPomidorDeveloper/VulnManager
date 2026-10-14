package adapters

import (
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/parsers"
)

func trivy() (Adapter, error) {
	return adapterOf(
		parsers.NewTrivy(),
		normalizers.Trivy(
			normalizers.CVSSFrom("nvd", "ghsa", "redhat", "bitnami"),
			normalizers.FromCVSS, normalizers.FromLabel,
		),
	)()
}
