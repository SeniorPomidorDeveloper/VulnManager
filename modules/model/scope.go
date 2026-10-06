package model

import (
	"crypto/sha256"
	"encoding/hex"
)

type Scope struct {
	TenantID  TenantID
	ProductID ProductID
	ContextID ContextID
}

func NewScope(tenantID TenantID, productID ProductID, contextID ContextID) (Scope, error) {
	if tenantID.IsEmpty() {
		return Scope{}, ErrEmptyTenant
	}
	if productID.IsEmpty() {
		return Scope{}, ErrEmptyProduct
	}
	return Scope{TenantID: tenantID, ProductID: productID, ContextID: contextID}, nil
}

func (s Scope) Key() ScopeKey {
	sum := sha256.Sum256([]byte(string(s.TenantID) + "/" + string(s.ProductID) + "/" + string(s.ContextID)))
	return ScopeKey(hex.EncodeToString(sum[:]))
}
