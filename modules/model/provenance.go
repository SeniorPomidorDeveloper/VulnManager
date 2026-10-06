package model

type Provenance struct {
	Tool                   string
	ToolVersion            string
	ScanID                 ScanID
	ContextSnapshotVersion string
}
