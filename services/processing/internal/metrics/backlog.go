package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"vulnmanager/services/processing/internal/store"
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
			"vulnmanager_processing_unprocessed_runs",
			"Completed import runs not processed yet.", nil, nil,
		),
		age: prometheus.NewDesc(
			"vulnmanager_processing_oldest_unprocessed_run_age_seconds",
			"Age of the oldest completed import run that processing has not handled.", nil, nil,
		),
		failures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vulnmanager_processing_backlog_scrape_failures_total",
			Help: "Scrapes where the unprocessed import runs could not be read from the database.",
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
