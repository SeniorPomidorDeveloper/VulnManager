package rawstore

import (
	"context"
	"errors"
	"io"
)

var ErrNotFound = errors.New("rawstore: object not found")

type Key struct {
	TenantID string
	ScanID   string
	SHA256   string
}

func (k Key) String() string {
	return k.TenantID + "/" + k.ScanID + "/" + k.SHA256
}

type Info struct {
	Size int64
}

type Store interface {
	Put(ctx context.Context, key Key, r io.Reader, size int64) error
	Get(ctx context.Context, key Key) (io.ReadCloser, error)
	Stat(ctx context.Context, key Key) (Info, error)
}
