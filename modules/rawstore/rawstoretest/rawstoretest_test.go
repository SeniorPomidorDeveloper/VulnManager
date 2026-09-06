package rawstoretest

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"

	"vulnmanager/modules/rawstore"
)

type memStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemStore() rawstore.Store {
	return &memStore{data: map[string][]byte{}}
}

func (s *memStore) Put(_ context.Context, key rawstore.Key, r io.Reader, _ int64) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key.String()] = b
	return nil
}

func (s *memStore) Get(_ context.Context, key rawstore.Key) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.data[key.String()]
	if !ok {
		return nil, rawstore.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (s *memStore) Stat(_ context.Context, key rawstore.Key) (rawstore.Info, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.data[key.String()]
	if !ok {
		return rawstore.Info{}, rawstore.ErrNotFound
	}
	return rawstore.Info{Size: int64(len(b))}, nil
}

func TestRunContractSuite_ExternalStore(t *testing.T) {
	RunContractSuite(t, newMemStore)
}
