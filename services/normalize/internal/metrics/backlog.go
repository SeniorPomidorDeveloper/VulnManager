package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"vulnmanager/services/normalize/internal/store"
)

const scrapeTimeout = 3 * time.Second

type BacklogSource interface {
	Backlog(ctx context.Context) (store.Backlog, error)
}

type backlogCollector struct {
	source   BacklogSource
	runs     *prometheus.Desc
	age      *prometheus.Desc
	failures prometheus.Counter
}

func NewBacklogCollector(source BacklogSource) prometheus.Collector {
	return &backlogCollector{
		source: source,
		runs: prometheus.NewDesc(
			"vulnmanager_normalize_unpublished_runs",
			"Completed import runs whose import.completed event was not published yet.", nil, nil,
		),
		age: prometheus.NewDesc(
			"vulnmanager_normalize_oldest_unpublished_run_age_seconds",
			"Age of the oldest completed import run without a published import.completed event.", nil, nil,
		),
		failures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vulnmanager_normalize_backlog_scrape_failures_total",
			Help: "Scrapes where the unpublished import runs could not be read from the database.",
		}),
	}
}

func (c *backlogCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.runs
	ch <- c.age
	ch <- c.failures.Desc()
}

func (c *backlogCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()
	backlog, err := c.source.Backlog(ctx)
	if err != nil {
		c.failures.Inc()
	} else {
		ch <- prometheus.MustNewConstMetric(c.runs, prometheus.GaugeValue, float64(backlog.Runs))
		ch <- prometheus.MustNewConstMetric(c.age, prometheus.GaugeValue, backlog.OldestAge.Seconds())
	}
	ch <- c.failures
}
