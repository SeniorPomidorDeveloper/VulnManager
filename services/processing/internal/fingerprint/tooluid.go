package fingerprint

import "vulnmanager/modules/model"

const (
	toolUIDID      StrategyID = "tool-uid"
	toolUIDVersion Version    = 1
)

type ToolUID struct{}

func (ToolUID) ID() StrategyID {
	return toolUIDID
}

func (ToolUID) Level() Level {
	return LevelToolUID
}

func (ToolUID) Version() Version {
	return toolUIDVersion
}

func (s ToolUID) Fingerprint(finding model.Finding) (Fingerprint, bool) {
	if finding.ToolFindingID == "" || finding.Provenance.Tool == "" {
		return Fingerprint{}, false
	}
	return digest(
		s,
		FindingField(finding.Provenance.Tool),
		FindingField(finding.Scope.Key()),
		FindingField(finding.ToolFindingID),
	), true
}
