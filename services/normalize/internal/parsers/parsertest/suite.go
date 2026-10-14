package parsertest

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vulnmanager/services/normalize/internal/parsers"
)

const (
	goldenMode = 0o644
)

var update = flag.Bool("update", false, "rewrite golden files")

type Options struct {
	Corpus    []string
	GoldenDir string
}

type goldenFinding struct {
	ToolFindingID string          `json:"tool_finding_id"`
	Kind          string          `json:"kind"`
	Title         string          `json:"title"`
	Description   string          `json:"description"`
	SeverityRaw   string          `json:"severity_raw"`
	VulnIDRaw     string          `json:"vuln_id_raw,omitempty"`
	Location      json.RawMessage `json:"location"`
	Diagnostics   []string        `json:"diagnostics"`
}

func Suite(t *testing.T, p parsers.Parser, opts Options) {
	t.Helper()

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
			if opts.GoldenDir != "" {
				checkGolden(t, filepath.Join(opts.GoldenDir, filepath.Base(path)+".json"), first)
			}
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

func checkGolden(t *testing.T, path string, found []parsers.RawFinding) {
	t.Helper()
	snapshot := make([]goldenFinding, 0, len(found))
	for _, finding := range found {
		diagnostics := make([]string, 0, len(finding.Diagnostics))
		for _, diagnostic := range finding.Diagnostics {
			diagnostics = append(diagnostics, string(diagnostic.Level)+":"+diagnostic.Code)
		}
		snapshot = append(snapshot, goldenFinding{
			ToolFindingID: string(finding.ToolFindingID),
			Kind:          finding.Kind.String(),
			Title:         finding.Title,
			Description:   finding.Description,
			SeverityRaw:   string(finding.SeverityRaw),
			VulnIDRaw:     string(finding.VulnIDRaw),
			Location:      finding.Location,
			Diagnostics:   diagnostics,
		})
	}
	got, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, goldenMode); err != nil {
			t.Fatal(err)
		}
		return
	}
	if want := read(t, path); !bytes.Equal(got, want) {
		t.Errorf("golden mismatch for %s; rerun with -update to rewrite", path)
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
