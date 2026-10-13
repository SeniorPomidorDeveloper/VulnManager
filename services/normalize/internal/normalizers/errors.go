package normalizers

import "errors"

var (
	ErrDuplicateNormalizer = errors.New("normalizers: duplicate normalizer id")
	ErrUnknownNormalizer   = errors.New("normalizers: unknown normalizer id")
)
