package blocks_test

import (
	"context"
	"errors"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers/blocks"
	"vulnmanager/services/normalize/internal/normalizers/normtest"
)

func testFormats(t *testing.T) []blocks.VulnFormat {
	t.Helper()
	specs := []struct {
		source model.VulnSource
		prefix string
		body   string
		rule   blocks.CaseRule
	}{
		{"cve", "CVE-", `\d{4}-\d{4,}`, blocks.CaseUpper},
		{"ghsa", "GHSA-", `([2-9cfghjmpqrvwx]{4}-){2}[2-9cfghjmpqrvwx]{4}`, blocks.CaseLower},
		{"bdu", "BDU:", `\d{4}-\d{5}`, blocks.CaseKeep},
	}
	formats := make([]blocks.VulnFormat, 0, len(specs))
	for _, spec := range specs {
		format, err := blocks.NewVulnFormat(spec.source, spec.prefix, spec.body, spec.rule)
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
	n := blocks.NewVulnID(testFormats(t))
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
	normtest.Suite(t, blocks.NewVulnID(testFormats(t)), []model.Finding{
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
		rule   blocks.CaseRule
	}{
		"empty prefix": {"cve", "", `\d+`, blocks.CaseUpper},
		"empty source": {"", "CVE-", `\d+`, blocks.CaseUpper},
		"unknown rule": {"cve", "CVE-", `\d+`, "title"},
		"bad regexp":   {"cve", "CVE-", `(`, blocks.CaseUpper},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := blocks.NewVulnFormat(c.source, c.prefix, c.body, c.rule)
			if !errors.Is(err, blocks.ErrInvalidVulnFormat) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestStandardVulnFormats(t *testing.T) {
	formats, err := blocks.StandardVulnFormats()
	if err != nil {
		t.Fatalf("formats: %v", err)
	}
	n := blocks.NewVulnID(formats)
	for raw, want := range map[model.VulnIDRaw]model.VulnID{
		"cve-2026-3449":       {Source: "cve", Value: "CVE-2026-3449"},
		"GHSA-RVG8-PWQ2-XJ7Q": {Source: "ghsa", Value: "GHSA-rvg8-pwq2-xj7q"},
		"nswg-eco-428":        {Source: "nswg", Value: "NSWG-ECO-428"},
		"osv-2020-111":        {Source: "osv", Value: "OSV-2020-111"},
		"pysec-2021-1":        {Source: "pysec", Value: "PYSEC-2021-1"},
		"BDU:2021-01234":      {Source: "bdu", Value: "BDU:2021-01234"},
	} {
		got := vulnFinding(raw)
		if err := n.Normalize(context.Background(), &got); err != nil || got.VulnID != want {
			t.Fatalf("%s: got %+v err=%v, want %+v", raw, got.VulnID, err, want)
		}
	}
}
