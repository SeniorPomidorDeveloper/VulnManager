package fingerprint

import (
	"encoding/json"
	"strings"

	"vulnmanager/modules/model"
)

type location struct {
	URI     string `json:"uri"`
	Target  string `json:"target"`
	Snippet string `json:"snippet"`
}

func (l location) path() string {
	if l.URI != "" {
		return l.URI
	}
	return l.Target
}

func (l location) code() string {
	return strings.Join(strings.Fields(l.Snippet), "")
}

func locationOf(finding model.Finding) location {
	var decoded location
	if len(finding.Location) == 0 || json.Unmarshal(finding.Location, &decoded) != nil {
		return location{}
	}
	return decoded
}
