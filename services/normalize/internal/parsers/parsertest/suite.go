package parsertest

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vulnmanager/services/normalize/internal/parsers"
)

const (
	defaultMinSniff = 0.5
	headSize        = 4096
)

type Options struct {
	Corpus   []string
	Foreign  []string
	MinSniff parsers.SniffScore
}

func Suite(t *testing.T, p parsers.Parser, opts Options) {
	t.Helper()
	if opts.MinSniff == 0 {
		opts.MinSniff = defaultMinSniff
	}

	t.Run("identity", func(t *testing.T) {
		id, version := p.ID(), p.Version()
		if id == "" || version == "" {
			t.Fatalf("empty id %q or version %q", id, version)
		}
		if again := p.ID(); again != id {
			t.Fatalf("id is not stable: %q then %q", id, again)
		}
		if again := p.Version(); again != version {
			t.Fatalf("version is not stable: %q then %q", version, again)
		}
	})

	t.Run("sniff", func(t *testing.T) {
		for _, path := range opts.Corpus {
			if got := p.Sniff(head(t, path)); got < opts.MinSniff {
				t.Errorf("sniff(%s) = %v, want >= %v", path, got, opts.MinSniff)
			}
		}
		for _, path := range opts.Foreign {
			if got := p.Sniff(head(t, path)); got >= opts.MinSniff {
				t.Errorf("sniff(%s) = %v, want < %v", path, got, opts.MinSniff)
			}
		}
	})

	for _, path := range opts.Corpus {
		data := read(t, path)
		t.Run("report/"+filepath.Base(path), func(t *testing.T) {
			first, err := parse(p, data)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			second, err := parse(p, data)
			if err != nil {
				t.Fatalf("second parse: %v", err)
			}
			if !reflect.DeepEqual(first, second) {
				t.Error("two runs on the same input differ")
			}
			checkFields(t, first)
		})
		t.Run("truncated/"+filepath.Base(path), func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("parser panicked on truncated input: %v", recovered)
				}
			}()
			_, _ = parse(p, data[:len(data)/2])
		})
	}
}

func parse(p parsers.Parser, data []byte) ([]parsers.RawFinding, error) {
	var found []parsers.RawFinding
	for finding, err := range p.Parse(context.Background(), bytes.NewReader(data), parsers.ScanMeta{}) {
		if err != nil {
			return found, err
		}
		found = append(found, finding)
	}
	return found, nil
}

func checkFields(t *testing.T, found []parsers.RawFinding) {
	t.Helper()
	for i, finding := range found {
		if finding.Title == "" {
			t.Errorf("finding %d: empty title", i)
		}
		if !json.Valid(finding.Raw) {
			t.Errorf("finding %d: raw is not valid json", i)
		}
		if finding.Location != nil && !json.Valid(finding.Location) {
			t.Errorf("finding %d: location is not valid json", i)
		}
	}
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func head(t *testing.T, path string) []byte {
	t.Helper()
	data := read(t, path)
	return data[:min(len(data), headSize)]
}
