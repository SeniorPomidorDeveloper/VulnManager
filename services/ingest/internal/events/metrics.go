package events

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"vulnmanager/services/ingest/internal/jobs"
)

const (
	resultOK    = "ok"
	resultError = "error"
)

type Metrics struct {
	published *prometheus.CounterVec
	duration  prometheus.Histogram
}

type instrumented struct {
	next    jobs.Publisher
	metrics *Metrics
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		published: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnmanager_ingest_events_published_total",
			Help: "report.received events published by ingest, by result.",
		}, []string{"result"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "vulnmanager_ingest_event_publish_duration_seconds",
			Help:    "Time to publish a report.received event and get the broker confirmation.",
			Buckets: prometheus.DefBuckets,
		}),
	}
	reg.MustRegister(m.published, m.duration)
	return m
}

func (m *Metrics) Wrap(next jobs.Publisher) jobs.Publisher {
	return instrumented{next: next, metrics: m}
}

func (i instrumented) Publish(ctx context.Context, event jobs.Event) error {
	start := time.Now()
	err := i.next.Publish(ctx, event)
	i.metrics.duration.Observe(time.Since(start).Seconds())
	result := resultOK
	if err != nil {
		result = resultError
	}
	i.metrics.published.WithLabelValues(result).Inc()
	return err
}
