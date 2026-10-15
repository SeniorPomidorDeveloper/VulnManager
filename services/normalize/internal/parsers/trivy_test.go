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

func TestTrivy_Suite(t *testing.T) {
	parsertest.Suite(t, parsers.NewTrivy(), parsertest.Options{
		Corpus:    []string{corpus + "/trivy/0.75.0/juice-shop.json"},
		GoldenDir: "testdata/golden/trivy",
	})
}

func trivyDoc(schema int, results string) string {
	return fmt.Sprintf(`{"SchemaVersion":%d,"ArtifactType":"filesystem","Results":[%s]}`, schema, results)
}

func trivyResult(target, body string) string {
	return fmt.Sprintf(`{"Target":%q,"Type":"npm",%s}`, target, body)
}

func parseTrivy(t *testing.T, doc string) []parsers.RawFinding {
	t.Helper()
	var found []parsers.RawFinding
	for finding, err := range parsers.NewTrivy().Parse(context.Background(), strings.NewReader(doc), parsers.ScanMeta{}) {
		if err != nil {
			t.Fatal(err)
		}
		found = append(found, finding)
	}
	return found
}

func TestTrivy_VulnerabilityMapping(t *testing.T) {
	vulnerability := `{"VulnerabilityID":"CVE-1","PkgName":"lodash","InstalledVersion":"4.0.0","FixedVersion":"4.1.0",` +
		`"Severity":"HIGH","Title":"Prototype pollution","Description":"details","PkgIdentifier":{"PURL":"pkg:npm/lodash@4.0.0"}}`

	found := parseTrivy(t, trivyDoc(2, trivyResult("package-lock.json", `"Vulnerabilities":[`+vulnerability+`]`)))

	if len(found) != 1 {
		t.Fatalf("got %d findings, want 1", len(found))
	}
	got := found[0]
	if got.Kind != model.KindSCA || got.Title != "Prototype pollution" || got.Description != "details" || got.SeverityRaw != "HIGH" {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got.ToolFindingID != "CVE-1|lodash|4.0.0|package-lock.json" {
		t.Fatalf("got tool finding id %q", got.ToolFindingID)
	}
	wantLocation := `{"target":"package-lock.json","package_type":"npm","package":"lodash",` +
		`"installed_version":"4.0.0","fixed_version":"4.1.0","purl":"pkg:npm/lodash@4.0.0"}`
	if string(got.Location) != wantLocation {
		t.Fatalf("got location %s", got.Location)
	}
	if string(got.Raw) != vulnerability {
		t.Fatalf("raw was modified: %s", got.Raw)
	}
}

func TestTrivy_TitleFallback(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		title string
	}{
		{name: "title", body: `{"VulnerabilityID":"CVE-1","Title":"t"}`, title: "t"},
		{name: "vulnerability id", body: `{"VulnerabilityID":"CVE-1"}`, title: "CVE-1"},
		{name: "nothing", body: `{}`, title: "unnamed vulnerability"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			found := parseTrivy(t, trivyDoc(2, trivyResult("a", `"Vulnerabilities":[`+tc.body+`]`)))

			if len(found) != 1 || found[0].Title != tc.title {
				t.Fatalf("got %+v, want title %q", found, tc.title)
			}
		})
	}
}

func TestTrivy_Degradation(t *testing.T) {
	tests := []struct {
		name     string
		doc      string
		wantCode string
	}{
		{name: "vulnerability is not an object", doc: trivyDoc(2, trivyResult("a", `"Vulnerabilities":["oops"]`)), wantCode: "invalid_vulnerability"},
		{name: "unexpected schema", doc: trivyDoc(3, trivyResult("a", `"Vulnerabilities":[{"VulnerabilityID":"CVE-1"}]`)), wantCode: "trivy_schema_version"},
		{name: "absolute target", doc: trivyDoc(2, trivyResult("/abs/package-lock.json", `"Vulnerabilities":[{"VulnerabilityID":"CVE-1"}]`)), wantCode: "absolute_path"},
		{name: "secrets are not copied", doc: trivyDoc(2, trivyResult("a", `"Secrets":[{"Match":"AKIA-never-copied"}]`)), wantCode: "unsupported_section"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			found := parseTrivy(t, tc.doc)

			if len(found) != 1 || len(found[0].Diagnostics) == 0 || found[0].Diagnostics[0].Code != tc.wantCode {
				t.Fatalf("got %+v, want diagnostic %q", found, tc.wantCode)
			}
			if strings.Contains(string(found[0].Raw), "AKIA") {
				t.Fatalf("secret value leaked into raw: %s", found[0].Raw)
			}
		})
	}
}

func TestTrivy_InvalidJSONIsAnError(t *testing.T) {
	for _, err := range parsers.NewTrivy().Parse(context.Background(), strings.NewReader(`{"Results":`), parsers.ScanMeta{}) {
		if err == nil {
			t.Fatal("expected a decode error")
		}
		return
	}
	t.Fatal("expected at least one yielded value")
}

func TestTrivy_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	doc := trivyDoc(2, trivyResult("a", `"Vulnerabilities":[{"VulnerabilityID":"CVE-1"}]`))

	for _, err := range parsers.NewTrivy().Parse(ctx, strings.NewReader(doc), parsers.ScanMeta{}) {
		if err == nil {
			t.Fatal("expected context error")
		}
		return
	}
	t.Fatal("expected at least one yielded value")
}

func TestTrivy_ToolVersionComesFromTheReport(t *testing.T) {
	doc := `{"SchemaVersion":2,"Trivy":{"Version":"0.75.0"},"Results":[{"Target":"package-lock.json","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-1","PkgName":"a"}]}]}`
	for finding, err := range parsers.NewTrivy().Parse(context.Background(), strings.NewReader(doc), parsers.ScanMeta{}) {
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if finding.ToolVersion != "0.75.0" {
			t.Fatalf("tool version %q", finding.ToolVersion)
		}
	}
}
