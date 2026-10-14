package store

import (
	"slices"
	"testing"

	"vulnmanager/modules/model"
)

func TestDiagnosticsJSON(t *testing.T) {
	tests := []struct {
		name        string
		diagnostics model.Diagnostics
		want        string
	}{
		{name: "none is an empty array", want: `[]`},
		{
			name:        "entries keep order and fields",
			diagnostics: model.Diagnostics{}.Append(model.DiagLevelWarn, "code", "message"),
			want:        `[{"level":"warn","code":"code","message":"message"}]`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := diagnosticsJSON(tc.diagnostics)

			if err != nil || string(got) != tc.want {
				t.Fatalf("got %s (err=%v), want %s", got, err, tc.want)
			}
		})
	}
}

func TestProvenanceJSON(t *testing.T) {
	got, err := provenanceJSON(model.Provenance{Tool: "trivy", ToolVersion: "0.75.0", ScanID: "scan-1"})

	want := `{"tool":"trivy","tool_version":"0.75.0","scan_id":"scan-1","context_snapshot_version":""}`
	if err != nil || string(got) != want {
		t.Fatalf("got %s (err=%v), want %s", got, err, want)
	}
}

func TestRatingsOf_CollectsCVSSAndTheScannerScore(t *testing.T) {
	score := model.Score(8.5)
	finding := model.Finding{
		Provenance:   model.Provenance{Tool: "semgrep"},
		ScannerScore: &score,
		CVSS: []model.CVSSScore{
			{Source: "nvd", Version: "3.1", Vector: "CVSS:3.1/AV:N", BaseScore: 9.8},
		},
	}

	got := ratingsOf(finding)

	want := []rating{
		{source: "nvd", scheme: "cvss", version: "3.1", vector: "CVSS:3.1/AV:N", score: 9.8},
		{source: "semgrep", scheme: "scanner", score: 8.5},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if len(ratingsOf(model.Finding{})) != 0 {
		t.Fatal("a finding without ratings must produce no rows")
	}
}
