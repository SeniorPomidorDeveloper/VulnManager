package model

type RawKey struct {
	TenantID TenantID
	ScanID   ScanID
	SHA256   string
}

func RawKeyFor(scope Scope, scanID ScanID, sha256 string) RawKey {
	return RawKey{TenantID: scope.TenantID, ScanID: scanID, SHA256: sha256}
}

func (k RawKey) String() string {
	return string(k.TenantID) + "/" + string(k.ScanID) + "/" + k.SHA256
}
