package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"

	"vulnmanager/modules/model"
)

const (
	genericID      ParserID      = "generic-json"
	genericVersion ParserVersion = "1"
	codeUnknown                  = "unknown_format"
)

type GenericJSON struct{}

func NewGenericJSON() GenericJSON {
	return GenericJSON{}
}

func (GenericJSON) ID() ParserID {
	return genericID
}

func (GenericJSON) Version() ParserVersion {
	return genericVersion
}

func (GenericJSON) Capabilities() Capabilities {
	return Capabilities{Formats: []FormatName{FormatJSON}}
}

func (GenericJSON) Parse(ctx context.Context, r io.Reader, _ ScanMeta) iter.Seq2[RawFinding, error] {
	return func(yield func(RawFinding, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(RawFinding{}, err)
			return
		}
		content, err := io.ReadAll(r)
		if err != nil {
			yield(RawFinding{}, fmt.Errorf("read report: %w", err))
			return
		}
		raw := json.RawMessage(content)
		if !json.Valid(content) {
			raw = json.RawMessage(fmt.Sprintf(`{"bytes":%d}`, len(content)))
		}
		yield(RawFinding{
			Kind:  model.KindUnknown,
			Title: "unparsed report",
			Raw:   raw,
			Diagnostics: model.Diagnostics{}.Append(
				model.DiagLevelWarn, codeUnknown, "no parser matches the report format",
			),
		}, nil)
	}
}
