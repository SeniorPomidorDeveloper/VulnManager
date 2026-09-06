package model

import (
	"crypto/sha256"
	"encoding/hex"
)

type Scope struct {
	TenantID  string
	ProductID string
	ContextID string
}

func NewScope(tenantID, productID, contextID string) (Scope, error) {
	if tenantID == "" {
		return Scope{}, ErrEmptyTenant
	}
	if productID == "" {
		return Scope{}, ErrEmptyProduct
	}
	return Scope{TenantID: tenantID, ProductID: productID, ContextID: contextID}, nil
}

func (s Scope) Key() string {
	sum := sha256.Sum256([]byte(s.TenantID + "/" + s.ProductID + "/" + s.ContextID))
	return hex.EncodeToString(sum[:])
}
