package events

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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
	next    Publisher
	metrics *Metrics
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		published: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnmanager_normalize_events_published_total",
			Help: "import.completed events published by normalize, by result.",
		}, []string{"result"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "vulnmanager_normalize_event_publish_duration_seconds",
			Help:    "Time to publish an import.completed event and get the broker confirmation.",
			Buckets: prometheus.DefBuckets,
		}),
	}
	reg.MustRegister(m.published, m.duration)
	return m
}

func (m *Metrics) Wrap(next Publisher) Publisher {
	return instrumented{next: next, metrics: m}
}

func (i instrumented) Publish(ctx context.Context, event Event) error {
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
