package store

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/gen/db"
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
