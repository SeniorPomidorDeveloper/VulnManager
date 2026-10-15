package blocks_test

import (
	"context"
	"slices"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers/blocks"
	"vulnmanager/services/normalize/internal/normalizers/normtest"
)

func cweFinding(raw ...model.CWERaw) model.Finding {
	return model.Finding{ToolFindingID: "id", CWERaw: raw}
}

func TestCWE_Normalize(t *testing.T) {
	cases := []struct {
		name string
		raw  []model.CWERaw
		want []model.CWEName
	}{
		{"plain", []model.CWERaw{"CWE-79"}, []model.CWEName{"CWE-79"}},
		{"semgrep tag with a title", []model.CWERaw{"CWE-89: Improper Neutralization of Special Elements"}, []model.CWEName{"CWE-89"}},
		{"codeql tag with leading zeros", []model.CWERaw{"external/cwe/cwe-079"}, []model.CWEName{"CWE-79"}},
		{"sorted numerically without duplicates", []model.CWERaw{"CWE-200", "CWE-22", "cwe-200", "CWE-59"}, []model.CWEName{"CWE-22", "CWE-59", "CWE-200"}},
		{"several in one entry", []model.CWERaw{"CWE-22, CWE-59"}, []model.CWEName{"CWE-22", "CWE-59"}},
		{"none", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cweFinding(c.raw...)
			if err := blocks.NewCWE().Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if !slices.Equal(got.CWE, c.want) || len(got.Diagnostics) != 0 {
				t.Fatalf("got %v diagnostics %+v, want %v", got.CWE, got.Diagnostics, c.want)
			}
		})
	}
}

func TestCWE_EntryWithoutANumberWarnsOnce(t *testing.T) {
	got := cweFinding("cwe-top25", "cwe-unknown", "CWE-20")
	if err := blocks.NewCWE().Normalize(context.Background(), &got); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !slices.Equal(got.CWE, []model.CWEName{"CWE-20"}) || len(got.Diagnostics) != 1 || !got.Diagnostics.Has("invalid_cwe") {
		t.Fatalf("got %v diagnostics %+v", got.CWE, got.Diagnostics)
	}
}

func TestCWE_Suite(t *testing.T) {
	normtest.Suite(t, blocks.NewCWE(), []model.Finding{
		cweFinding("CWE-22", "external/cwe/cwe-079"), cweFinding("cwe-top25"), cweFinding(),
	})
}
