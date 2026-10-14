package parsers

import (
	"context"
	"encoding/json"
	"io"
	"iter"

	"vulnmanager/modules/model"
)

type (
	FormatName    string
	ParserID      string
	ParserVersion string
)

const (
	FormatJSON FormatName = "json"

	codeAbsolutePath = "absolute_path"
)

type ScanMeta struct {
	Tool        model.ToolName
	ToolVersion model.ToolVersion
	ScanID      model.ScanID
}

type RawFinding struct {
	ToolFindingID model.ToolFindingID
	Kind          model.Kind
	Title         string
	Description   string
	SeverityRaw   model.SeverityRaw
	VulnIDRaw     model.VulnIDRaw
	PURLRaw       model.PURLRaw
	CVSSVectors   []model.CVSSCandidate
	Location      json.RawMessage
	Raw           json.RawMessage
	Diagnostics   model.Diagnostics
}

type Capabilities struct {
	Formats []FormatName
	Kinds   []model.Kind
	Tools   []model.ToolName
}

type Parser interface {
	ID() ParserID
	Version() ParserVersion
	Capabilities() Capabilities
	Parse(ctx context.Context, r io.Reader, meta ScanMeta) iter.Seq2[RawFinding, error]
}
