package blocks_test

import (
	"context"
	"slices"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers/blocks"
	"vulnmanager/services/normalize/internal/normalizers/normtest"
)

const v31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

func cvssFinding(candidates ...model.CVSSCandidate) model.Finding {
	return model.Finding{ToolFindingID: "id", CVSSRaw: candidates}
}

func TestCVSS_KeepsEveryValidCandidateWithItsSource(t *testing.T) {
	got := cvssFinding(
		model.CVSSCandidate{Source: "nvd", Vector: v31Vector},
		model.CVSSCandidate{Source: "nvd", Vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},
		model.CVSSCandidate{Source: "ghsa", Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"},
	)
	if err := blocks.NewCVSS().Normalize(context.Background(), &got); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	want := []model.CVSSScore{
		{Source: "nvd", Version: "3.1", Vector: v31Vector, BaseScore: 9.8},
		{Source: "nvd", Version: "2.0", Vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P", BaseScore: 6.8},
		{Source: "ghsa", Version: "3.1", Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", BaseScore: 3.3},
	}
	if !slices.Equal(got.CVSS, want) || len(got.Diagnostics) != 0 {
		t.Fatalf("cvss %+v diagnostics %+v", got.CVSS, got.Diagnostics)
	}
}

func TestCVSS_SkipsInvalidCandidatesWithOneWarning(t *testing.T) {
	got := cvssFinding(
		model.CVSSCandidate{Source: "a", Vector: "CVSS:3.1/AV:N"},
		model.CVSSCandidate{Source: "b", Vector: v31Vector},
		model.CVSSCandidate{Source: "c", Vector: "garbage"},
	)
	if err := blocks.NewCVSS().Normalize(context.Background(), &got); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(got.CVSS) != 1 || got.CVSS[0].Source != "b" || len(got.Diagnostics) != 1 || !got.Diagnostics.Has("invalid_cvss") {
		t.Fatalf("cvss %+v diagnostics %+v", got.CVSS, got.Diagnostics)
	}
}

func TestCVSS_Suite(t *testing.T) {
	normtest.Suite(t, blocks.NewCVSS(), []model.Finding{
		cvssFinding(model.CVSSCandidate{Source: "nvd", Vector: v31Vector}),
		cvssFinding(model.CVSSCandidate{Source: "x", Vector: "garbage"}),
		cvssFinding(),
	})
}
