package model

import "testing"

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

func TestDiagnostics_Has(t *testing.T) {
	d := Diagnostics{}.Append(DiagLevelInfo, "known", "message")
	if !d.Has("known") || d.Has("missing") {
		t.Fatalf("Has misreports codes in %+v", d)
	}
}
