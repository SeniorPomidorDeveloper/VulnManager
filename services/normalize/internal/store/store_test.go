package store

import (
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
