package pipeline

import (
	"context"
	"time"
)

type Recorder interface {
	ObserveDuration(stage string, d time.Duration)
	IncErrors(stage string)
}

type SpanStarter interface {
	StartSpan(ctx context.Context, name string) (context.Context, func())
}
