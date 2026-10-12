package model

type Provenance struct {
	Tool                   ToolName
	ToolVersion            ToolVersion
	ScanID                 ScanID
	ContextSnapshotVersion string
}
