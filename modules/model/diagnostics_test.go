package model

import (
	"encoding/json"
	"testing"
)

func TestDiagnostics_Append(t *testing.T) {
	var d Diagnostics
	d = d.Append(DiagLevelWarn, "unknown_format", "could not sniff parser")
	if len(d) != 1 {
		t.Fatalf("got len=%d, want 1", len(d))
	}
	if d[0].Level != DiagLevelWarn || d[0].Code != "unknown_format" {
		t.Fatalf("unexpected entry: %+v", d[0])
	}
}

func TestDiagnostics_JSONRoundTrip(t *testing.T) {
	var d Diagnostics
	d = d.Append(DiagLevelInfo, "no_tool_profile", "")

	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Diagnostics
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 || got[0] != d[0] {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, d)
	}
}
