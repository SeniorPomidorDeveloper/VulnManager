package events

import (
	"context"

	"vulnmanager/services/ingest/internal/jobs"
)

type Disabled struct{}

func (Disabled) Publish(context.Context, jobs.Event) error {
	return nil
}
