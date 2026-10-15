package parsers

import (
	"encoding/json"
	"slices"
	"testing"

	"vulnmanager/modules/model"
)

func TestTrivyCVSSCandidates_KeepEverySourceInStableOrder(t *testing.T) {
	sources := map[string]trivyCVSS{
		"redhat": {V3Vector: "v3-redhat"},
		"nvd":    {V2Vector: "v2-nvd", V3Vector: "v3-nvd", V40Vector: "v4-nvd"},
		"ghsa":   {},
	}
	want := []model.CVSSCandidate{
		{Source: "nvd", Vector: "v3-nvd"},
		{Source: "nvd", Vector: "v4-nvd"},
		{Source: "nvd", Vector: "v2-nvd"},
		{Source: "redhat", Vector: "v3-redhat"},
	}
	got := trivyCVSSCandidates(sources)
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if trivyCVSSCandidates(nil) != nil {
		t.Fatal("no sources must give no candidates")
	}
}

func TestSecurityScore(t *testing.T) {
	score := func(value model.Score) *model.Score { return &value }
	cases := map[string]*model.Score{
		`"7.5"`:  score(7.5),
		`9.8`:    score(9.8),
		`"0"`:    score(0),
		`"high"`: nil,
		`null`:   nil,
		``:       nil,
	}
	for raw, want := range cases {
		t.Run(raw, func(t *testing.T) {
			got := securityScore(json.RawMessage(raw))
			if (got == nil) != (want == nil) || got != nil && *got != *want {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestCWEList_KeepsOnlyCWEEntries(t *testing.T) {
	got := cweList([]string{"security", "CWE-79: XSS", "external/cwe/cwe-089", "owasp-a1"})
	want := []model.CWERaw{"CWE-79: XSS", "external/cwe/cwe-089"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
