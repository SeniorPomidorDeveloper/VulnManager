package rawstoretest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"vulnmanager/modules/rawstore"
)

func RunContractSuite(t *testing.T, newStore func() rawstore.Store) {
	t.Helper()

	t.Run("put then get returns the same bytes", func(t *testing.T) {
		s := newStore()
		key := rawstore.Key{TenantID: "t1", ScanID: "scan-1", SHA256: "aaaa"}
		content := []byte("hello raw report")

		if err := s.Put(context.Background(), key, bytes.NewReader(content), int64(len(content))); err != nil {
			t.Fatalf("Put returned error: %v", err)
		}

		r, err := s.Get(context.Background(), key)
		if err != nil {
			t.Fatalf("Get returned error: %v", err)
		}
		defer func() { _ = r.Close() }()

		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll returned error: %v", err)
		}
		if !bytes.Equal(got, content) {
			t.Fatalf("got %q, want %q", got, content)
		}
	})

	t.Run("stat returns the size written", func(t *testing.T) {
		s := newStore()
		key := rawstore.Key{TenantID: "t1", ScanID: "scan-2", SHA256: "bbbb"}
		content := []byte("some report content")

		if err := s.Put(context.Background(), key, bytes.NewReader(content), int64(len(content))); err != nil {
			t.Fatalf("Put returned error: %v", err)
		}

		info, err := s.Stat(context.Background(), key)
		if err != nil {
			t.Fatalf("Stat returned error: %v", err)
		}
		if info.Size != int64(len(content)) {
			t.Fatalf("got size %d, want %d", info.Size, len(content))
		}
	})

	t.Run("put is idempotent for the same key", func(t *testing.T) {
		s := newStore()
		key := rawstore.Key{TenantID: "t1", ScanID: "scan-3", SHA256: "cccc"}
		content := []byte("idempotent content")

		if err := s.Put(context.Background(), key, bytes.NewReader(content), int64(len(content))); err != nil {
			t.Fatalf("first Put returned error: %v", err)
		}
		if err := s.Put(context.Background(), key, bytes.NewReader(content), int64(len(content))); err != nil {
			t.Fatalf("second Put returned error: %v", err)
		}

		r, err := s.Get(context.Background(), key)
		if err != nil {
			t.Fatalf("Get returned error: %v", err)
		}
		defer func() { _ = r.Close() }()

		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll returned error: %v", err)
		}
		if !bytes.Equal(got, content) {
			t.Fatalf("got %q, want %q", got, content)
		}
	})

	t.Run("get on a missing key returns ErrNotFound", func(t *testing.T) {
		s := newStore()
		key := rawstore.Key{TenantID: "t1", ScanID: "missing", SHA256: "dddd"}

		if _, err := s.Get(context.Background(), key); !errors.Is(err, rawstore.ErrNotFound) {
			t.Fatalf("got err=%v, want %v", err, rawstore.ErrNotFound)
		}
	})

	t.Run("stat on a missing key returns ErrNotFound", func(t *testing.T) {
		s := newStore()
		key := rawstore.Key{TenantID: "t1", ScanID: "missing", SHA256: "eeee"}

		if _, err := s.Stat(context.Background(), key); !errors.Is(err, rawstore.ErrNotFound) {
			t.Fatalf("got err=%v, want %v", err, rawstore.ErrNotFound)
		}
	})
}
