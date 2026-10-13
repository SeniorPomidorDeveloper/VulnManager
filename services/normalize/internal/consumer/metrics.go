package consumer

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	messages *prometheus.CounterVec
	failures *prometheus.CounterVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		messages: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnmanager_normalize_messages_total",
			Help: "report.received messages consumed by normalize, by verdict.",
		}, []string{"verdict"}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnmanager_normalize_message_failures_total",
			Help: "Failures to settle a message with the broker, by step.",
		}, []string{"step"}),
	}
	reg.MustRegister(m.messages, m.failures)
	return m
}
