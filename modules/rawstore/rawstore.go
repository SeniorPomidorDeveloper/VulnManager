package rawstore

import (
	"context"
	"errors"
	"io"

	"vulnmanager/modules/model"
)

var ErrNotFound = errors.New("rawstore: object not found")

type Key struct {
	TenantID model.TenantID
	ScanID   model.ScanID
	SHA256   string
}

func KeyFor(scope model.Scope, scanID model.ScanID, sha256 string) Key {
	return Key{TenantID: scope.TenantID, ScanID: scanID, SHA256: sha256}
}

func (k Key) String() string {
	return string(k.TenantID) + "/" + string(k.ScanID) + "/" + k.SHA256
}

type Info struct {
	Size int64
}

type Store interface {
	Put(ctx context.Context, key Key, r io.Reader, size int64) error
	Get(ctx context.Context, key Key) (io.ReadCloser, error)
	Stat(ctx context.Context, key Key) (Info, error)
}
