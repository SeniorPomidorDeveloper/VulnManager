package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func sampleProvenance() Provenance {
	return Provenance{Tool: "trivy", ToolVersion: "0.50.0", ScanID: "scan1"}
}

func TestProvenance_JSONRoundTrip(t *testing.T) {
	p := sampleProvenance()

	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Provenance
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != p {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, p)
	}
}

func TestProvenance_JSONStable(t *testing.T) {
	p := sampleProvenance()
	b1, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b2, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("marshaling the same value twice produced different output:\n%s\nvs\n%s", b1, b2)
	}
}

func TestProvenance_JSONGolden(t *testing.T) {
	p := sampleProvenance()
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b = append(b, '\n')

	path := filepath.Join("testdata", "provenance.json")
	if *updateGolden {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if string(b) != string(want) {
		t.Fatalf("golden mismatch, got:\n%s\nwant:\n%s\n(run with -update to refresh)", b, want)
	}
}
