package parsers_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/parsers"
	"vulnmanager/services/normalize/internal/parsers/parsertest"
)

func TestSARIF_Suite(t *testing.T) {
	parsertest.Suite(t, parsers.NewSARIF(), parsertest.Options{
		Corpus:    []string{corpus + "/semgrep/1.180.0/juice-shop.sarif"},
		GoldenDir: "testdata/golden/sarif",
	})
}

func sarifDoc(version, rules, results string) string {
	return fmt.Sprintf(
		`{"version":%q,"runs":[{"tool":{"driver":{"rules":[%s]}},"results":[%s]}]}`, version, rules, results,
	)
}

func parseSARIF(t *testing.T, doc string) []parsers.RawFinding {
	t.Helper()
	var found []parsers.RawFinding
	for finding, err := range parsers.NewSARIF().Parse(context.Background(), strings.NewReader(doc), parsers.ScanMeta{}) {
		if err != nil {
			t.Fatal(err)
		}
		found = append(found, finding)
	}
	return found
}

func TestSARIF_Mapping(t *testing.T) {
	tests := []struct {
		name         string
		rules        string
		result       string
		wantTitle    string
		wantSeverity model.SeverityRaw
	}{
		{
			name:         "result level and rule short description win",
			rules:        `{"id":"r1","name":"rule-name","shortDescription":{"text":"short"},"defaultConfiguration":{"level":"note"}}`,
			result:       `{"ruleId":"r1","level":"error","message":{"text":"m"}}`,
			wantTitle:    "short",
			wantSeverity: "error",
		},
		{
			name:         "rule default level and name",
			rules:        `{"id":"r1","name":"rule-name","defaultConfiguration":{"level":"note"}}`,
			result:       `{"ruleId":"r1","message":{"text":"m"}}`,
			wantTitle:    "rule-name",
			wantSeverity: "note",
		},
		{
			name:         "rule id and default severity",
			result:       `{"ruleId":"r1","message":{"text":"m"}}`,
			wantTitle:    "r1",
			wantSeverity: "warning",
		},
		{
			name:         "nothing known",
			result:       `{"message":{"text":"m"}}`,
			wantTitle:    "unnamed finding",
			wantSeverity: "warning",
		},
		{
			name:         "rule index beats rule id",
			rules:        `{"id":"other","shortDescription":{"text":"first"}},{"id":"r1","shortDescription":{"text":"second"}}`,
			result:       `{"ruleId":"r1","ruleIndex":0,"message":{"text":"m"}}`,
			wantTitle:    "first",
			wantSeverity: "warning",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			found := parseSARIF(t, sarifDoc("2.1.0", tc.rules, tc.result))

			if len(found) != 1 {
				t.Fatalf("got %d findings, want 1", len(found))
			}
			if found[0].Title != tc.wantTitle || found[0].SeverityRaw != tc.wantSeverity {
				t.Fatalf("got title %q severity %q, want %q %q", found[0].Title, found[0].SeverityRaw, tc.wantTitle, tc.wantSeverity)
			}
			if found[0].Kind != model.KindSAST {
				t.Fatalf("got kind %v, want sast", found[0].Kind)
			}
		})
	}
}

func TestSARIF_Location(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		wantURI  string
		wantDiag int
	}{
		{name: "relative", uri: "src/app.py", wantURI: "src/app.py"},
		{name: "absolute file uri", uri: "file:///home/dev/app.py", wantURI: "/home/dev/app.py", wantDiag: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := fmt.Sprintf(
				`{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":%q},"region":{"startLine":3,"startColumn":5}}}]}`,
				tc.uri,
			)

			found := parseSARIF(t, sarifDoc("2.1.0", "", result))

			wantLocation := fmt.Sprintf(`{"uri":%q,"start_line":3,"start_column":5}`, tc.wantURI)
			if string(found[0].Location) != wantLocation {
				t.Fatalf("got location %s, want %s", found[0].Location, wantLocation)
			}
			if len(found[0].Diagnostics) != tc.wantDiag {
				t.Fatalf("got %d diagnostics, want %d", len(found[0].Diagnostics), tc.wantDiag)
			}
			if got := string(found[0].ToolFindingID); got != "r|"+tc.wantURI+"|3|5" {
				t.Fatalf("got tool finding id %q", got)
			}
		})
	}
}

func TestSARIF_Degradation(t *testing.T) {
	tests := []struct {
		name     string
		doc      string
		wantCode string
		wantRaw  string
	}{
		{name: "result is not an object", doc: sarifDoc("2.1.0", "", `"oops"`), wantCode: "invalid_result", wantRaw: `"oops"`},
		{name: "unexpected version", doc: sarifDoc("2.0.0", "", `{"message":{"text":"m"}}`), wantCode: "sarif_version"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			found := parseSARIF(t, tc.doc)

			if len(found) != 1 || len(found[0].Diagnostics) == 0 || found[0].Diagnostics[0].Code != tc.wantCode {
				t.Fatalf("got %+v, want diagnostic %q", found, tc.wantCode)
			}
			if tc.wantRaw != "" && string(found[0].Raw) != tc.wantRaw {
				t.Fatalf("got raw %s, want %s", found[0].Raw, tc.wantRaw)
			}
		})
	}
}

func TestSARIF_MultipleRunsKeepOrder(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"results":[{"ruleId":"a","message":{"text":"1"}}]},{"results":[{"ruleId":"b","message":{"text":"2"}}]}]}`

	found := parseSARIF(t, doc)

	if len(found) != 2 || found[0].Title != "a" || found[1].Title != "b" {
		t.Fatalf("got %+v", found)
	}
}

func TestSARIF_InvalidJSONIsAnError(t *testing.T) {
	for _, err := range parsers.NewSARIF().Parse(context.Background(), strings.NewReader(`{"runs":`), parsers.ScanMeta{}) {
		if err == nil {
			t.Fatal("expected a decode error")
		}
		return
	}
	t.Fatal("expected at least one yielded value")
}

func TestSARIF_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, err := range parsers.NewSARIF().Parse(ctx, strings.NewReader(sarifDoc("2.1.0", "", `{"message":{"text":"m"}}`)), parsers.ScanMeta{}) {
		if err == nil {
			t.Fatal("expected context error")
		}
		return
	}
	t.Fatal("expected at least one yielded value")
}
