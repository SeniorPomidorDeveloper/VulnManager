package parsers_test

import (
	"context"
	"strings"
	"testing"

	"vulnmanager/services/normalize/internal/parsers"
	"vulnmanager/services/normalize/internal/parsers/parsertest"
)

const corpus = "../../../../testdata/corpus"

func TestGenericJSON_Suite(t *testing.T) {
	parsertest.Suite(t, parsers.NewGenericJSON(), parsertest.Options{
		Corpus:    []string{corpus + "/trivy/0.75.0/juice-shop.json", corpus + "/semgrep/1.180.0/juice-shop.sarif"},
		GoldenDir: "testdata/golden/generic-json",
	})
}

func TestGenericJSON_NotJSONIsKeptWithDiagnostics(t *testing.T) {
	parser := parsers.NewGenericJSON()

	for finding, err := range parser.Parse(context.Background(), strings.NewReader("plain text"), parsers.ScanMeta{}) {
		if err != nil {
			t.Fatal(err)
		}
		if string(finding.Raw) != `{"bytes":10}` {
			t.Fatalf("got raw %s", finding.Raw)
		}
		if len(finding.Diagnostics) != 1 || finding.Diagnostics[0].Code != "unknown_format" {
			t.Fatalf("got diagnostics %+v", finding.Diagnostics)
		}
	}
}

func TestGenericJSON_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, err := range parsers.NewGenericJSON().Parse(ctx, strings.NewReader("{}"), parsers.ScanMeta{}) {
		if err == nil {
			t.Fatal("expected context error")
		}
	}
}
