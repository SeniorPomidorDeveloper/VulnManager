package fingerprint

import (
	"strings"

	"vulnmanager/modules/model"
)

const (
	identityID      StrategyID = "identity"
	identityVersion Version    = 1
)

type Identity struct{}

func (Identity) ID() StrategyID {
	return identityID
}

func (Identity) Level() Level {
	return LevelIdentity
}

func (Identity) Version() Version {
	return identityVersion
}

func (s Identity) Fingerprint(finding model.Finding) (Fingerprint, bool) {
	if finding.VulnID.IsZero() {
		return Fingerprint{}, false
	}
	return digest(
		s,
		FindingField(finding.Scope.Key()),
		FindingField(finding.Kind.String()),
		FindingField(finding.VulnID.Source),
		FindingField(finding.VulnID.Value),
		componentKey(finding.Component),
		FindingField(locationOf(finding).path()),
	), true
}

func componentKey(component model.Component) FindingField {
	if component.PURL != "" {
		return FindingField(component.PURL)
	}
	return FindingField(strings.Join([]string{
		string(component.Type), component.Namespace, component.Name, component.Version,
	}, "/"))
}
