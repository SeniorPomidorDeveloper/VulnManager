package fingerprint

import "vulnmanager/modules/model"

const (
	structuralID      StrategyID = "structural"
	structuralVersion Version    = 1
)

type Structural struct{}

func (Structural) ID() StrategyID {
	return structuralID
}

func (Structural) Level() Level {
	return LevelStructural
}

func (Structural) Version() Version {
	return structuralVersion
}

func (s Structural) Fingerprint(finding model.Finding) (Fingerprint, bool) {
	place := locationOf(finding)
	if finding.RuleID == "" || place.path() == "" || place.code() == "" {
		return Fingerprint{}, false
	}
	return digest(
		s,
		FindingField(finding.Scope.Key()),
		FindingField(finding.RuleID),
		FindingField(place.path()),
		FindingField(place.code()),
	), true
}
