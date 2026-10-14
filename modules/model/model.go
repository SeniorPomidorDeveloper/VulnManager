package model

import (
	"encoding/json"
	"time"
)

type Finding struct {
	ID            FindingID
	ImportRunID   ImportRunID
	Scope         Scope
	ToolFindingID ToolFindingID
	Kind          Kind
	Title         string
	Description   string
	SeverityRaw   SeverityRaw
	Severity      Severity
	VulnIDRaw     VulnIDRaw
	VulnID        VulnID
	CVSSRaw       []CVSSCandidate
	ScannerScore  *Score
	PURLRaw       PURLRaw
	Component     Component
	CVSS          []CVSSScore
	Location      json.RawMessage
	Raw           json.RawMessage
	Provenance    Provenance
	AlgoVersion   string
	DetectedAt    time.Time
	Diagnostics   Diagnostics
}
