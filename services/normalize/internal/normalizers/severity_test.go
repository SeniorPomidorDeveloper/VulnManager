package normalizers_test

import (
	"context"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/normalizers/normtest"
)

var testScale = normalizers.SeverityScale{
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
	n := normalizers.NewSeverity(testScale, normalizers.SeverityPolicy{normalizers.FromLabel}, nil)
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
	label, vector := normalizers.FromLabel, normalizers.FromCVSS
	both := withCVSS(finding("low"), cvssScore("nvd", "3.1", 9.8))
	cases := []struct {
		name   string
		policy normalizers.SeverityPolicy
		in     model.Finding
		want   model.Severity
	}{
		{"cvss first", normalizers.SeverityPolicy{vector, label}, both, model.SeverityCritical},
		{"label first", normalizers.SeverityPolicy{label, vector}, both, model.SeverityLow},
		{"skips missing cvss", normalizers.SeverityPolicy{vector, label}, finding("error"), model.SeverityHigh},
		{"source not in policy is ignored", normalizers.SeverityPolicy{label}, both, model.SeverityLow},
		{"nothing resolves", normalizers.SeverityPolicy{vector}, finding("low"), model.SeverityUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.in
			if err := normalizers.NewSeverity(testScale, c.policy, nil).Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if got.Severity != c.want {
				t.Fatalf("got %v, want %v", got.Severity, c.want)
			}
		})
	}
}

func TestSeverity_VersionIncludesThePolicy(t *testing.T) {
	policy := normalizers.SeverityPolicy{normalizers.FromCVSS, normalizers.FromLabel}
	cases := map[string]normalizers.CVSSOrder{"2(cvss>label)": nil, "2(cvss>label;cvss=nvd,ghsa)": normalizers.CVSSFrom("nvd", "ghsa")}
	for want, order := range cases {
		if got := normalizers.NewSeverity(testScale, policy, order).Version(); got != normalizers.NormalizerVersion(want) {
			t.Fatalf("version %q, want %q", got, want)
		}
	}
}

func TestSeverity_Suite(t *testing.T) {
	policy := normalizers.SeverityPolicy{normalizers.FromCVSS, normalizers.FromLabel}
	normtest.Suite(t, normalizers.NewSeverity(testScale, policy, normalizers.CVSSFrom("nvd")), []model.Finding{
		finding("error"), finding("weird"), withCVSS(finding("low"), cvssScore("nvd", "3.1", 7.5)),
	})
}

func TestStandardScales(t *testing.T) {
	merged := normalizers.MergeScales(normalizers.LabelScale(), normalizers.SARIFLevelScale())
	for label, want := range map[model.SeverityRaw]model.Severity{
		"critical": model.SeverityCritical, "moderate": model.SeverityMedium, "error": model.SeverityHigh, "note": model.SeverityLow,
	} {
		if merged[label] != want {
			t.Fatalf("%s: got %v, want %v", label, merged[label], want)
		}
	}
}

func TestSeverity_CVSSPicksByVersionThenSourceOrder(t *testing.T) {
	policy := normalizers.SeverityPolicy{normalizers.FromCVSS}
	cases := []struct {
		name   string
		order  normalizers.CVSSOrder
		scores []model.CVSSScore
		want   model.Severity
	}{
		{"listed source first", normalizers.CVSSFrom("nvd", "ghsa"), []model.CVSSScore{cvssScore("ghsa", "3.1", 9.8), cvssScore("nvd", "3.1", 5)}, model.SeverityMedium},
		{"other order, other winner", normalizers.CVSSFrom("ghsa", "nvd"), []model.CVSSScore{cvssScore("ghsa", "3.1", 9.8), cvssScore("nvd", "3.1", 5)}, model.SeverityCritical},
		{"v3 beats v2 of a better source", normalizers.CVSSFrom("nvd", "redhat"), []model.CVSSScore{cvssScore("nvd", "2.0", 9), cvssScore("redhat", "3.1", 3)}, model.SeverityLow},
		{"unlisted sources go last by name", normalizers.CVSSFrom("nvd"), []model.CVSSScore{cvssScore("zzz", "3.1", 9.8), cvssScore("aaa", "3.1", 4)}, model.SeverityMedium},
		{"v2 bands have no critical", normalizers.CVSSFrom("nvd"), []model.CVSSScore{cvssScore("nvd", "2.0", 10)}, model.SeverityHigh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := withCVSS(finding(""), c.scores...)
			if err := normalizers.NewSeverity(testScale, policy, c.order).Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if got.Severity != c.want {
				t.Fatalf("got %v, want %v", got.Severity, c.want)
			}
		})
	}
}
