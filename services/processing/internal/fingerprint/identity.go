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
		s.Level(), s.Version(),
		string(finding.Scope.Key()),
		finding.Kind.String(),
		string(finding.VulnID.Source),
		finding.VulnID.Value,
		componentKey(finding.Component),
		locationOf(finding).path(),
	), true
}

func componentKey(component model.Component) string {
	if component.PURL != "" {
		return string(component.PURL)
	}
	return strings.Join([]string{
		string(component.Type), component.Namespace, component.Name, component.Version,
	}, "/")
}
