package model

type Provenance struct {
	Tool                   string `json:"tool"`
	ToolVersion            string `json:"tool_version"`
	ScanID                 string `json:"scan_id"`
	ContextSnapshotVersion string `json:"context_snapshot_version,omitempty"`
}
