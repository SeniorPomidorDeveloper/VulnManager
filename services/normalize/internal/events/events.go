package events

import (
	"context"

	"vulnmanager/modules/model"
)

type Event struct {
	RunID  model.ImportRunID
	Scope  model.Scope
	Tool   model.ToolName
	ScanID model.ScanID
}

type Publisher interface {
	Publish(ctx context.Context, event Event) error
}

type Disabled struct{}

func (Disabled) Publish(context.Context, Event) error {
	return nil
}
