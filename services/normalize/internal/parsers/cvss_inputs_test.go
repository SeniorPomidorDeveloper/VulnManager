package parsers

import (
	"slices"
	"testing"

	"vulnmanager/modules/model"
)

func TestTrivyCVSSCandidates_KeepEverySourceInStableOrder(t *testing.T) {
	sources := map[string]trivyCVSS{
		"redhat": {V3Vector: "v3-redhat"},
		"nvd":    {V2Vector: "v2-nvd", V3Vector: "v3-nvd"},
		"ghsa":   {},
	}
	want := []model.CVSSCandidate{
		{Source: "nvd", Vector: "v3-nvd"}, {Source: "nvd", Vector: "v2-nvd"}, {Source: "redhat", Vector: "v3-redhat"},
	}
	got := trivyCVSSCandidates(sources)
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if trivyCVSSCandidates(nil) != nil {
		t.Fatal("no sources must give no candidates")
	}
}
