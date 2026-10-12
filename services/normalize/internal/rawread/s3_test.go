package rawread

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"vulnmanager/modules/model"
)

const (
	bucket    = "raw"
	reportKey = "t1/scan-1/abcd"
	notFound  = `<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>missing</Message></Error>`
	location  = `<?xml version="1.0"?><LocationConstraint>garage</LocationConstraint>`
)

func newReader(t *testing.T, objects map[string]string) *S3Reader {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("location") {
			_, _ = io.WriteString(w, location)
			return
		}
		body, ok := objects[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, notFound)
			return
		}
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)

	reader, err := NewS3Reader(S3Config{
		Endpoint:        Endpoint(strings.TrimPrefix(server.URL, "http://")),
		AccessKeyID:     "key",
		SecretAccessKey: "secret",
		Bucket:          bucket,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func TestS3Reader_ReadsTheObjectNamedByTheKey(t *testing.T) {
	key := model.RawKey{TenantID: "t1", ScanID: "scan-1", SHA256: "abcd"}
	reader := newReader(t, map[string]string{"/" + bucket + "/" + reportKey: "report body"})

	object, err := reader.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()

	body, err := io.ReadAll(object)
	if err != nil || string(body) != "report body" {
		t.Fatalf("got %q (err=%v), want the report body", body, err)
	}
}

func TestS3Reader_MissingObjectIsNotFound(t *testing.T) {
	reader := newReader(t, nil)

	_, err := reader.Get(context.Background(), model.RawKey{TenantID: "t1", ScanID: "scan-1", SHA256: "abcd"})

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}
