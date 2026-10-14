package blocks_test

import (
	"cmp"
	"context"
	"slices"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/cvss"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/normalizers/blocks"
	"vulnmanager/services/normalize/internal/normalizers/normtest"
)

var testScale = blocks.SeverityScale{
	"error":    model.SeverityHigh,
	"warning":  model.SeverityMedium,
	"critical": model.SeverityCritical,
	"low":      model.SeverityLow,
}

func finding(raw model.SeverityRaw) model.Finding {
	return model.Finding{ToolFindingID: model.ToolFindingID("id/" + string(raw)), SeverityRaw: raw}
}

func withCVSS(f model.Finding, scores ...model.CVSSScore) model.Finding {
	f.CVSS = scores
	return f
}

func cvssScore(source model.CVSSSource, version model.CVSSVersion, base model.Score) model.CVSSScore {
	return model.CVSSScore{Source: source, Version: version, Vector: "v", BaseScore: base}
}

func TestSeverity_Label(t *testing.T) {
	cases := []struct {
		name string
		in   model.Finding
		want model.Severity
	}{
		{"label", finding("ERROR"), model.SeverityHigh},
		{"trimmed", finding(" Critical "), model.SeverityCritical},
		{"unknown label", finding("weird"), model.SeverityUnknown},
		{"empty label", finding(""), model.SeverityUnknown},
	}
	n := normalizers.NewSeverity(blocks.SeverityByPriority(testScale, nil, blocks.SeverityFromLabel))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.in
			if err := n.Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if got.Severity != c.want {
				t.Fatalf("got %v, want %v", got.Severity, c.want)
			}
			if wantDiag := c.want == model.SeverityUnknown; got.Diagnostics.Has("unknown_severity") != wantDiag {
				t.Fatalf("diagnostics %+v", got.Diagnostics)
			}
		})
	}
}

func TestSeverity_PolicyDecidesWhoWins(t *testing.T) {
	label, vector := blocks.SeverityFromLabel, blocks.SeverityFromCVSS
	both := withCVSS(finding("low"), cvssScore("nvd", "3.1", 9.8))
	cases := []struct {
		name   string
		policy []blocks.SeveritySource
		in     model.Finding
		want   model.Severity
	}{
		{"cvss first", []blocks.SeveritySource{vector, label}, both, model.SeverityCritical},
		{"label first", []blocks.SeveritySource{label, vector}, both, model.SeverityLow},
		{"skips missing cvss", []blocks.SeveritySource{vector, label}, finding("error"), model.SeverityHigh},
		{"source not in policy is ignored", []blocks.SeveritySource{label}, both, model.SeverityLow},
		{"nothing resolves", []blocks.SeveritySource{vector}, finding("low"), model.SeverityUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.in
			if err := normalizers.NewSeverity(blocks.SeverityByPriority(testScale, nil, c.policy...)).Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if got.Severity != c.want {
				t.Fatalf("got %v, want %v", got.Severity, c.want)
			}
		})
	}
}

func TestSeverity_VersionIncludesThePolicy(t *testing.T) {
	policy := []blocks.SeveritySource{blocks.SeverityFromCVSS, blocks.SeverityFromLabel}
	cases := map[string]blocks.CVSSOrder{"2(cvss>label)": nil, "2(cvss>label;cvss=nvd,ghsa)": blocks.CVSSSources("nvd", "ghsa")}
	for want, order := range cases {
		if got := normalizers.NewSeverity(blocks.SeverityByPriority(testScale, order, policy...)).Version(); got != normalizers.NormalizerVersion(want) {
			t.Fatalf("version %q, want %q", got, want)
		}
	}
}

func TestSeverity_Suite(t *testing.T) {
	policy := []blocks.SeveritySource{blocks.SeverityFromCVSS, blocks.SeverityFromLabel}
	normtest.Suite(t, normalizers.NewSeverity(blocks.SeverityByPriority(testScale, blocks.CVSSSources("nvd"), policy...)), []model.Finding{
		finding("error"), finding("weird"), withCVSS(finding("low"), cvssScore("nvd", "3.1", 7.5)),
	})
}

func TestStandardScales(t *testing.T) {
	merged := blocks.MergeScales(blocks.LabelScale(), blocks.SARIFLevelScale())
	for label, want := range map[model.SeverityRaw]model.Severity{
		"critical": model.SeverityCritical, "moderate": model.SeverityMedium, "error": model.SeverityHigh, "note": model.SeverityLow,
	} {
		if merged[label] != want {
			t.Fatalf("%s: got %v, want %v", label, merged[label], want)
		}
	}
}

func TestSeverity_CVSSPicksByVersionThenSourceOrder(t *testing.T) {
	policy := []blocks.SeveritySource{blocks.SeverityFromCVSS}
	cases := []struct {
		name   string
		order  blocks.CVSSOrder
		scores []model.CVSSScore
		want   model.Severity
	}{
		{"listed source first", blocks.CVSSSources("nvd", "ghsa"), []model.CVSSScore{cvssScore("ghsa", "3.1", 9.8), cvssScore("nvd", "3.1", 5)}, model.SeverityMedium},
		{"other order, other winner", blocks.CVSSSources("ghsa", "nvd"), []model.CVSSScore{cvssScore("ghsa", "3.1", 9.8), cvssScore("nvd", "3.1", 5)}, model.SeverityCritical},
		{"v3 beats v2 of a better source", blocks.CVSSSources("nvd", "redhat"), []model.CVSSScore{cvssScore("nvd", "2.0", 9), cvssScore("redhat", "3.1", 3)}, model.SeverityLow},
		{"unlisted sources go last by name", blocks.CVSSSources("nvd"), []model.CVSSScore{cvssScore("zzz", "3.1", 9.8), cvssScore("aaa", "3.1", 4)}, model.SeverityMedium},
		{"v2 bands have no critical", blocks.CVSSSources("nvd"), []model.CVSSScore{cvssScore("nvd", "2.0", 10)}, model.SeverityHigh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := withCVSS(finding(""), c.scores...)
			if err := normalizers.NewSeverity(blocks.SeverityByPriority(testScale, c.order, policy...)).Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if got.Severity != c.want {
				t.Fatalf("got %v, want %v", got.Severity, c.want)
			}
		})
	}
}

type maxScoreCalculator struct{}

func (maxScoreCalculator) Version() normalizers.NormalizerVersion { return "max" }

func (maxScoreCalculator) Calculate(f *model.Finding) (model.Severity, bool) {
	if len(f.CVSS) == 0 {
		return model.SeverityUnknown, false
	}
	top := slices.MaxFunc(f.CVSS, func(a, b model.CVSSScore) int { return cmp.Compare(a.BaseScore, b.BaseScore) })
	return cvss.SeverityFor(cvss.Score(top.BaseScore), cvss.Version(top.Version)), true
}

func TestSeverity_AToolMayBringItsOwnCalculator(t *testing.T) {
	n := normalizers.NewSeverity(maxScoreCalculator{})
	got := withCVSS(finding(""), cvssScore("nvd", "3.1", 5), cvssScore("ghsa", "3.1", 9.8))
	if err := n.Normalize(context.Background(), &got); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got.Severity != model.SeverityCritical || n.Version() != "2(max)" {
		t.Fatalf("severity %v version %q", got.Severity, n.Version())
	}
}
