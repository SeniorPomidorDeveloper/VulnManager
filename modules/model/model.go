package model

import (
	"encoding/json"
	"time"
)

type Finding struct {
	ID            FindingID
	ImportRunID   ImportRunID
	Scope         Scope
	ToolFindingID string
	Kind          Kind
	Title         string
	Description   string
	SeverityRaw   string
	Location      json.RawMessage
	Raw           json.RawMessage
	Provenance    Provenance
	AlgoVersion   string
	DetectedAt    time.Time
	Diagnostics   Diagnostics
}
