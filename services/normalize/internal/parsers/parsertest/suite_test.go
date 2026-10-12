package parsertest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"iter"
	"os"
	"path/filepath"
	"testing"

	"vulnmanager/services/normalize/internal/parsers"
	"vulnmanager/services/normalize/internal/parsers/parsertest"
)

const reportFileMode = 0o644

type fake struct{}

func (fake) ID() parsers.ParserID { return "fake" }

func (fake) Version() parsers.ParserVersion { return "1" }

func (fake) Capabilities() parsers.Capabilities { return parsers.Capabilities{} }

func (fake) Sniff(head []byte) parsers.SniffScore {
	if bytes.HasPrefix(head, []byte("{")) {
		return 1
	}
	return 0
}

func (fake) Parse(_ context.Context, r io.Reader, _ parsers.ScanMeta) iter.Seq2[parsers.RawFinding, error] {
	return func(yield func(parsers.RawFinding, error) bool) {
		if _, err := io.Copy(io.Discard, r); err != nil {
			yield(parsers.RawFinding{}, err)
			return
		}
		yield(parsers.RawFinding{Title: "finding", Raw: json.RawMessage(`{}`)}, nil)
	}
}

func write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), reportFileMode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSuite_AcceptsAConformingParser(t *testing.T) {
	parsertest.Suite(t, fake{}, parsertest.Options{
		Corpus:  []string{write(t, "report.json", `{"results":[1,2,3]}`)},
		Foreign: []string{write(t, "notes.txt", "plain text")},
	})
}
