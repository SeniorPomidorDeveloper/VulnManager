package normalizers_test

import (
	"context"
	"errors"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
	"vulnmanager/services/normalize/internal/normalizers/normtest"
)

func testFormats(t *testing.T) []normalizers.VulnFormat {
	t.Helper()
	specs := []struct {
		source model.VulnSource
		prefix string
		body   string
		rule   normalizers.CaseRule
	}{
		{"cve", "CVE-", `\d{4}-\d{4,}`, normalizers.CaseUpper},
		{"ghsa", "GHSA-", `([2-9cfghjmpqrvwx]{4}-){2}[2-9cfghjmpqrvwx]{4}`, normalizers.CaseLower},
		{"bdu", "BDU:", `\d{4}-\d{5}`, normalizers.CaseKeep},
	}
	formats := make([]normalizers.VulnFormat, 0, len(specs))
	for _, spec := range specs {
		format, err := normalizers.NewVulnFormat(spec.source, spec.prefix, spec.body, spec.rule)
		if err != nil {
			t.Fatalf("format %s: %v", spec.source, err)
		}
		formats = append(formats, format)
	}
	return formats
}

func vulnFinding(raw model.VulnIDRaw) model.Finding {
	return model.Finding{ToolFindingID: model.ToolFindingID("id/" + string(raw)), VulnIDRaw: raw}
}

func TestVulnID_Normalize(t *testing.T) {
	cases := []struct {
		name    string
		raw     model.VulnIDRaw
		want    model.VulnID
		wantAdv bool
	}{
		{"cve lowercase", " cve-2021-0001 ", model.VulnID{Source: "cve", Value: "CVE-2021-0001"}, false},
		{"ghsa uppercase body", "GHSA-RVG8-PWQ2-XJ7Q", model.VulnID{Source: "ghsa", Value: "GHSA-rvg8-pwq2-xj7q"}, false},
		{"bdu kept", "bdu:2021-01234", model.VulnID{Source: "bdu", Value: "BDU:2021-01234"}, false},
		{"unknown prefix", "NSWG-ECO-428", model.VulnID{Source: model.VulnSourceUnknown, Value: "NSWG-ECO-428"}, true},
		{"known prefix, bad body", "CVE-abc", model.VulnID{Source: model.VulnSourceUnknown, Value: "CVE-abc"}, true},
		{"prefix only", "CVE-", model.VulnID{Source: model.VulnSourceUnknown, Value: "CVE-"}, true},
		{"empty", "  ", model.VulnID{}, false},
	}
	n := normalizers.NewVulnID(testFormats(t))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := vulnFinding(c.raw)
			if err := n.Normalize(context.Background(), &got); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if got.VulnID != c.want {
				t.Fatalf("got %+v, want %+v", got.VulnID, c.want)
			}
			if got.Diagnostics.Has("unknown_vuln_id_format") != c.wantAdv {
				t.Fatalf("diagnostics %+v", got.Diagnostics)
			}
		})
	}
}

func TestVulnID_Suite(t *testing.T) {
	normtest.Suite(t, normalizers.NewVulnID(testFormats(t)), []model.Finding{
		vulnFinding("cve-2021-0001"),
		vulnFinding("GHSA-RVG8-PWQ2-XJ7Q"),
		vulnFinding("NSWG-ECO-428"),
		vulnFinding(""),
	})
}

func TestNewVulnFormat_RejectsBrokenSpecs(t *testing.T) {
	cases := map[string]struct {
		source model.VulnSource
		prefix string
		body   string
		rule   normalizers.CaseRule
	}{
		"empty prefix": {"cve", "", `\d+`, normalizers.CaseUpper},
		"empty source": {"", "CVE-", `\d+`, normalizers.CaseUpper},
		"unknown rule": {"cve", "CVE-", `\d+`, "title"},
		"bad regexp":   {"cve", "CVE-", `(`, normalizers.CaseUpper},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := normalizers.NewVulnFormat(c.source, c.prefix, c.body, c.rule)
			if !errors.Is(err, normalizers.ErrInvalidVulnFormat) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
