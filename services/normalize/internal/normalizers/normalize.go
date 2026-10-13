package normalizers

import (
	"context"

	"vulnmanager/modules/model"
)

type (
	NormalizerID      string
	NormalizerVersion string
)

type Normalizer interface {
	ID() NormalizerID
	Version() NormalizerVersion
	Applies(kind model.Kind) bool
	Normalize(ctx context.Context, finding *model.Finding) error
}
