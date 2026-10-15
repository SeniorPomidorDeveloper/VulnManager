package dedup

import (
	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/fingerprint"
)

type Record struct {
	Finding   model.FindingID
	Kind      model.Kind
	Severity  model.Severity
	Rule      model.RuleID
	Vuln      model.VulnID
	Component model.Component
	CWE       []model.CWEName
	Path      string
	Code      string
}

func RecordOf(finding model.Finding) Record {
	path, code := fingerprint.PlaceOf(finding)
	return Record{
		Finding:   finding.ID,
		Kind:      finding.Kind,
		Severity:  finding.Severity,
		Rule:      finding.RuleID,
		Vuln:      finding.VulnID,
		Component: finding.Component,
		CWE:       finding.CWE,
		Path:      path,
		Code:      code,
	}
}
