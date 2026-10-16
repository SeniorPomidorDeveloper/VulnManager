package dedup_test

import (
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/dedup"
	"vulnmanager/services/processing/internal/dedup/deduptest"
)

func sca(vuln, purl string, severity model.Severity) dedup.Record {
	return dedup.Record{
		Kind:      model.KindSCA,
		Severity:  severity,
		Vuln:      model.VulnID{Source: "cve", Value: vuln},
		Component: model.Component{PURL: model.PURL(purl)},
	}
}

func sast(rule, path, code string, cwe ...model.CWEName) dedup.Record {
	return dedup.Record{Kind: model.KindSAST, Rule: model.RuleID(rule), Path: path, Code: code, CWE: cwe}
}

func weighted(t *testing.T) dedup.ByKind {
	t.Helper()
	scorer, err := dedup.DefaultByKind()
	if err != nil {
		t.Fatal(err)
	}
	return scorer
}

func ofKind(kind model.Kind, record dedup.Record) dedup.Record {
	record.Kind = kind
	return record
}

func TestWeightedVerdicts(t *testing.T) {
	cwe := model.CWEName("CWE-89")
	tests := []struct {
		name string
		a, b dedup.Record
		want dedup.Verdict
	}{
		{"same vuln and component", sca("CVE-1", "pkg:x@1", model.SeverityHigh), sca("CVE-1", "pkg:x@1", model.SeverityHigh), dedup.VerdictMerge},
		{"same vuln and component, severity differs", sca("CVE-1", "pkg:x@1", model.SeverityHigh), sca("CVE-1", "pkg:x@1", model.SeverityCritical), dedup.VerdictMerge},
		{"same vuln, other version", sca("CVE-1", "pkg:x@1", model.SeverityHigh), sca("CVE-1", "pkg:x@2", model.SeverityHigh), dedup.VerdictSeparate},
		{"other vuln, same component", sca("CVE-1", "pkg:x@1", model.SeverityHigh), sca("CVE-2", "pkg:x@1", model.SeverityHigh), dedup.VerdictSeparate},
		{"same vuln, component unknown on one side", sca("CVE-1", "pkg:x@1", model.SeverityHigh), sca("CVE-1", "", model.SeverityHigh), dedup.VerdictSeparate},
		{"same rule, path and code", sast("r", "a.go", "x", cwe), sast("r", "a.go", "x", cwe), dedup.VerdictMerge},
		{"same rule and path, other code", sast("r", "a.go", "x"), sast("r", "a.go", "y"), dedup.VerdictSeparate},
		{"other tool, same path and code", sast("r1", "a.go", "x", cwe), sast("r2", "a.go", "x", cwe), dedup.VerdictReview},
		{"same code in other file", sast("r", "a.go", "x"), sast("r", "b.go", "x"), dedup.VerdictReview},
	}
	scorer := weighted(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scorer.Score(tc.a, tc.b); got.Verdict != tc.want {
				t.Fatalf("got %s (%.2f) %+v, want %s", got.Verdict, got.Confidence, got.Reasons, tc.want)
			}
		})
	}
}

func TestWeightedNeverMergesAcrossKinds(t *testing.T) {
	a := sca("CVE-1", "pkg:x@1", model.SeverityHigh)
	b := a
	b.Kind = model.KindContainer

	got := weighted(t).Score(a, b)

	if got.Verdict != dedup.VerdictSeparate || got.Confidence != 0 || got.Reasons[0].Feature != dedup.FeatureKind {
		t.Fatalf("got %+v", got)
	}
}

func TestWeightedClampsConfidenceToOne(t *testing.T) {
	heavy := map[dedup.FeatureID]dedup.Weight{}
	for _, feature := range dedup.DefaultFeatures() {
		heavy[feature.ID()] = dedup.Weight{Agree: 900}
	}
	scorer, err := dedup.NewWeighted(dedup.DefaultFeatures(), heavy, dedup.DefaultThresholds())
	if err != nil {
		t.Fatal(err)
	}
	a := sca("CVE-1", "pkg:x@1", model.SeverityHigh)

	got := scorer.Score(a, a)

	if got.Confidence != 1 || got.Verdict != dedup.VerdictMerge {
		t.Fatalf("got %+v", got)
	}
}

func TestByKindUsesProfileOfTheKind(t *testing.T) {
	scorer := weighted(t)
	check := dedup.Record{Rule: "CKV_1", Path: "main.tf", Code: "res"}

	tests := map[model.Kind]dedup.Verdict{
		model.KindIaC:    dedup.VerdictMerge,
		model.KindSecret: dedup.VerdictMerge,
		model.KindSAST:   dedup.VerdictMerge,
		model.KindDAST:   dedup.VerdictMerge,
	}
	for kind, want := range tests {
		t.Run(kind.String(), func(t *testing.T) {
			if got := scorer.Score(ofKind(kind, check), ofKind(kind, check)); got.Verdict != want {
				t.Fatalf("got %+v, want %s", got, want)
			}
		})
	}

	rulePath := dedup.Record{Rule: "CKV_1", Path: "main.tf"}
	if got := scorer.Score(ofKind(model.KindIaC, rulePath), ofKind(model.KindIaC, rulePath)); got.Verdict != dedup.VerdictReview {
		t.Fatalf("iac rule and path alone must stay in review: %+v", got)
	}
	if got := scorer.Score(ofKind(model.KindSAST, rulePath), ofKind(model.KindSAST, rulePath)); got.Verdict != dedup.VerdictSeparate {
		t.Fatalf("sast rule and path alone must stay separate: %+v", got)
	}
}

func TestWeightedContract(t *testing.T) {
	deduptest.RunScorerSuite(t, weighted(t), []deduptest.Pair{
		{Name: "identical sca", A: sca("CVE-1", "pkg:x@1", model.SeverityHigh), B: sca("CVE-1", "pkg:x@1", model.SeverityHigh)},
		{Name: "different sast", A: sast("r", "a.go", "x"), B: sast("q", "b.go", "y")},
		{Name: "empty records", A: dedup.Record{}, B: dedup.Record{}},
	})
}

func TestNewWeightedRejectsBrokenConfig(t *testing.T) {
	valid := dedup.DefaultWeights()
	missing := dedup.DefaultWeights()
	delete(missing, dedup.FeatureVuln)
	negative := dedup.DefaultWeights()
	negative[dedup.FeaturePath] = dedup.Weight{Agree: -1}

	tests := map[string]struct {
		weights    map[dedup.FeatureID]dedup.Weight
		thresholds dedup.Thresholds
	}{
		"missing weight":     {missing, dedup.DefaultThresholds()},
		"negative agree":     {negative, dedup.DefaultThresholds()},
		"review above merge": {valid, dedup.Thresholds{Merge: 500, Review: 600}},
		"merge above scale":  {valid, dedup.Thresholds{Merge: 1200, Review: 600}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := dedup.NewWeighted(dedup.DefaultFeatures(), tc.weights, tc.thresholds); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSameToolUIDMergesWithoutAnySnippet(t *testing.T) {
	a := sast("r", "a.go", "")
	a.ToolUID = "v1:l0:sha256:aa"
	b := a

	for _, kind := range []model.Kind{model.KindSAST, model.KindSCA, model.KindIaC, model.KindSecret, model.KindDAST} {
		got := weighted(t).Score(ofKind(kind, a), ofKind(kind, b))
		if got.Verdict != dedup.VerdictMerge {
			t.Fatalf("%s: got %+v", kind, got)
		}
	}
}

func TestDifferentToolUIDDoesNotBlockOtherEvidence(t *testing.T) {
	a := sast("r", "a.go", "x")
	b := sast("r", "a.go", "x")
	a.ToolUID, b.ToolUID = "v1:l0:sha256:aa", "v1:l0:sha256:bb"

	if got := weighted(t).Score(a, b); got.Verdict != dedup.VerdictMerge {
		t.Fatalf("got %+v", got)
	}
}
