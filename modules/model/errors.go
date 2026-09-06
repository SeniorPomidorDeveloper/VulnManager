package model

import "errors"

var (
	ErrEmptyTenant  = errors.New("model: tenant is required")
	ErrEmptyProduct = errors.New("model: product is required")
	ErrUnknownKind  = errors.New("model: unknown kind")
)
