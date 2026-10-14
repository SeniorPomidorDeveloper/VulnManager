package blocks

import "vulnmanager/modules/model"

type vulnFormatSpec struct {
	source model.VulnSource
	prefix string
	body   string
	rule   CaseRule
}

func StandardVulnFormats() ([]VulnFormat, error) {
	specs := []vulnFormatSpec{
		{"cve", "CVE-", `\d{4}-\d{4,}`, CaseUpper},
		{"ghsa", "GHSA-", `([2-9cfghjmpqrvwx]{4}-){2}[2-9cfghjmpqrvwx]{4}`, CaseLower},
		{"nswg", "NSWG-", `[a-z]+-\d+`, CaseUpper},
		{"osv", "OSV-", `\d{4}-\d+`, CaseUpper},
		{"pysec", "PYSEC-", `\d{4}-\d+`, CaseUpper},
		{"bdu", "BDU:", `\d{4}-\d{5}`, CaseKeep},
	}
	formats := make([]VulnFormat, 0, len(specs))
	for _, spec := range specs {
		format, err := NewVulnFormat(spec.source, spec.prefix, spec.body, spec.rule)
		if err != nil {
			return nil, err
		}
		formats = append(formats, format)
	}
	return formats, nil
}
