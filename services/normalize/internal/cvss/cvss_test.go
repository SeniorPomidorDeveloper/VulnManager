package cvss_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/cvss"
)

const corpusReport = "../../../../testdata/corpus/trivy/0.75.0/juice-shop.json"

func TestParse_BaseScore(t *testing.T) {
	cases := []struct {
		vector string
		want   cvss.Score
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", 3.3},
		{"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 4.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5},
		{"AV:N/AC:M/Au:N/C:P/I:P/A:P", 6.8},
		{"AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0},
		{"AV:N/AC:L/Au:N/C:N/I:N/A:N", 0},
	}
	for _, c := range cases {
		t.Run(c.vector, func(t *testing.T) {
			got, err := cvss.Parse(c.vector)
			if err != nil || got.BaseScore != c.want {
				t.Fatalf("score %v err %v, want %v", got.BaseScore, err, c.want)
			}
		})
	}
}

func TestParse_CanonicalVector(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"CVSS:3.1/UI:N/AV:N/AC:L/PR:N/S:U/C:H/I:H/A:H/E:P/RL:O", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{" cvss:3.0/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h ", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"(AV:N/AC:L/Au:N/C:P/I:P/A:P)", "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			got, err := cvss.Parse(c.raw)
			if err != nil || got.Vector != c.want {
				t.Fatalf("vector %q err %v, want %q", got.Vector, err, c.want)
			}
		})
	}
}

func TestParse_RejectsBrokenVectors(t *testing.T) {
	for _, raw := range []string{
		"", "CVSS:3.1", "CVSS:9.9/AV:N", "CVSS:3.1/AV:N/AC:L", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:N", "AV:N/AC:L/Au:N/C:P/I:P", "garbage",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := cvss.Parse(raw); !errors.Is(err, cvss.ErrInvalidVector) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestSeverityFor(t *testing.T) {
	cases := []struct {
		score   cvss.Score
		version cvss.Version
		want    model.Severity
	}{
		{0, cvss.V31, model.SeverityInfo},
		{0.1, cvss.V31, model.SeverityLow},
		{3.9, cvss.V31, model.SeverityLow},
		{4.0, cvss.V31, model.SeverityMedium},
		{6.9, cvss.V30, model.SeverityMedium},
		{7.0, cvss.V31, model.SeverityHigh},
		{8.9, cvss.V31, model.SeverityHigh},
		{9.0, cvss.V31, model.SeverityCritical},
		{10, cvss.V30, model.SeverityCritical},
		{9.0, cvss.V2, model.SeverityHigh},
		{7.0, cvss.V2, model.SeverityHigh},
		{4.0, cvss.V2, model.SeverityMedium},
	}
	for _, c := range cases {
		if got := cvss.SeverityFor(c.score, c.version); got != c.want {
			t.Fatalf("%v %s: got %v, want %v", c.score, c.version, got, c.want)
		}
	}
}

type corpusReportShape struct {
	Results []struct {
		Vulnerabilities []struct {
			CVSS map[string]struct {
				V3Vector  string  `json:"V3Vector"`
				V3Score   float64 `json:"V3Score"`
				V2Vector  string  `json:"V2Vector"`
				V2Score   float64 `json:"V2Score"`
				V40Vector string  `json:"V40Vector"`
				V40Score  float64 `json:"V40Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

const scannerDisagrees = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"

func TestParse_MatchesScannerScoresOnCorpus(t *testing.T) {
	content, err := os.ReadFile(corpusReport)
	if err != nil {
		t.Fatal(err)
	}
	var report corpusReportShape
	if err := json.Unmarshal(content, &report); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, result := range report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			for _, source := range vulnerability.CVSS {
				for vector, want := range map[string]float64{source.V3Vector: source.V3Score, source.V2Vector: source.V2Score, source.V40Vector: source.V40Score} {
					if vector == "" || vector == scannerDisagrees {
						continue
					}
					got, err := cvss.Parse(vector)
					if err != nil || float64(got.BaseScore) != want {
						t.Fatalf("%s: score %v err %v, scanner says %v", vector, got.BaseScore, err, want)
					}
					checked++
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("corpus has no vectors")
	}
}

func TestParse_DisagreesWithAWrongScannerScore(t *testing.T) {
	got, err := cvss.Parse(scannerDisagrees)
	if err != nil || got.BaseScore != 9.0 {
		t.Fatalf("score %v err %v: the scanner reports 9.1, the specification gives 9.0", got.BaseScore, err)
	}
}

func TestParse_V40(t *testing.T) {
	cases := []struct {
		vector string
		want   cvss.Score
	}{
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0},
		{"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N/E:P", 1.9},
	}
	for _, c := range cases {
		t.Run(c.vector, func(t *testing.T) {
			got, err := cvss.Parse(c.vector)
			if err != nil || got.Version != cvss.V40 || got.BaseScore != c.want {
				t.Fatalf("version %s score %v err %v, want %v", got.Version, got.BaseScore, err, c.want)
			}
		})
	}
}

func TestParse_V40CanonicalVector(t *testing.T) {
	got, err := cvss.Parse(" cvss:4.0/ui:n/av:n/ac:l/at:n/pr:n/vc:h/vi:h/va:h/sc:n/si:n/sa:n/e:x/s:p/u:green/cr:h ")
	want := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H"
	if err != nil || got.Vector != want {
		t.Fatalf("vector %q err %v, want %q", got.Vector, err, want)
	}
}

func TestParse_V40RejectsBrokenVectors(t *testing.T) {
	const base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	for _, raw := range []string{
		"CVSS:4.0/AV:N", base + "/AV:N", base + "/E:Q", base + "/U:Purple", base + "/ZZ:A",
		"CVSS:4.0/AV:NA/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:4.0/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := cvss.Parse(raw); !errors.Is(err, cvss.ErrInvalidVector) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
