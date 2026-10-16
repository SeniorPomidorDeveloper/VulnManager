package store

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/gen/db"
	"vulnmanager/services/processing/internal/dedup"
)

func text(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: true}
}

func testRun(t *testing.T) Run {
	t.Helper()
	scope, err := model.NewScope("tenant", "product", "")
	if err != nil {
		t.Fatal(err)
	}
	return Run{ID: model.ImportRunID(uuid.NewString()), Scope: scope, Tool: "trivy"}
}

func TestToFindingMapsRow(t *testing.T) {
	run := testRun(t)
	id := uuid.New()
	row := db.ListRunFindingsRow{
		ID: id, ToolFindingID: "tool-id", Kind: "sca", RuleID: text("rule"),
		VulnSource: text("cve"), VulnID: text("CVE-2024-1"), Location: []byte(`{"target":"go.mod"}`),
		Purl: text("pkg:golang/x/y@1"), ComponentType: text("golang"), Name: text("y"), Version: text("1"),
	}

	got, err := toFinding(run, row)
	if err != nil {
		t.Fatal(err)
	}

	if got.ID != model.FindingID(id.String()) || got.Kind != model.KindSCA || got.RuleID != "rule" {
		t.Fatalf("unexpected finding: %+v", got)
	}
	if got.VulnID != (model.VulnID{Source: "cve", Value: "CVE-2024-1"}) {
		t.Fatalf("vuln id: %+v", got.VulnID)
	}
	if got.Component.PURL != "pkg:golang/x/y@1" || got.Component.Name != "y" || got.Provenance.Tool != "trivy" {
		t.Fatalf("component or tool: %+v", got)
	}
}

func TestToFindingWithoutOptionalParts(t *testing.T) {
	got, err := toFinding(testRun(t), db.ListRunFindingsRow{ID: uuid.New(), Kind: "sast"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.VulnID.IsZero() || !got.Component.IsZero() || got.RuleID != "" {
		t.Fatalf("expected empty optional parts: %+v", got)
	}
}

func TestToFindingRejectsUnknownKind(t *testing.T) {
	if _, err := toFinding(testRun(t), db.ListRunFindingsRow{ID: uuid.New(), Kind: "bogus"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestToFindingReadsSeverityAndCWE(t *testing.T) {
	got, err := toFinding(testRun(t), db.ListRunFindingsRow{
		ID: uuid.New(), Kind: "sast", Severity: "high", Cwe: []string{"CWE-79", "CWE-89"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Severity != model.SeverityHigh || len(got.CWE) != 2 || got.CWE[1] != "CWE-89" {
		t.Fatalf("got %+v", got)
	}
}

func TestToFindingTreatsUnknownSeverityAsUnknown(t *testing.T) {
	got, err := toFinding(testRun(t), db.ListRunFindingsRow{ID: uuid.New(), Kind: "sast", Severity: "weird"})
	if err != nil || got.Severity != model.SeverityUnknown {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestReasonRecordsKeepEveryReason(t *testing.T) {
	got := reasonRecords([]dedup.MatchReason{
		{Feature: dedup.FeatureVuln, Signal: dedup.SignalAgree, Points: 500},
		{Feature: dedup.FeatureSeverity, Signal: dedup.SignalDisagree, Points: -50},
	})

	want := []reasonRecord{{"vuln", "agree", 500}, {"severity", "disagree", -50}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseIDsRejectsNonUUID(t *testing.T) {
	if _, err := parseIDs([]model.FindingID{"not-a-uuid"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestToFindingPrefersRecordedTool(t *testing.T) {
	run := testRun(t)
	got, err := toFinding(run, db.ListRunFindingsRow{ID: uuid.New(), Kind: "sast", Tool: "semgrep"})
	if err != nil || got.Provenance.Tool != "semgrep" {
		t.Fatalf("got %+v, %v", got, err)
	}
	fallback, err := toFinding(run, db.ListRunFindingsRow{ID: uuid.New(), Kind: "sast"})
	if err != nil || fallback.Provenance.Tool != run.Tool {
		t.Fatalf("got %+v, %v", fallback, err)
	}
}
