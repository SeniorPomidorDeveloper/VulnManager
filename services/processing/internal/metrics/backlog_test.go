package metrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"vulnmanager/services/processing/internal/store"
)

type fakeBacklog struct {
	backlog store.Backlog
	err     error
}

func (f fakeBacklog) Backlog(context.Context) (store.Backlog, error) {
	return f.backlog, f.err
}

func TestBacklogCollectorExposesCountAndAge(t *testing.T) {
	source := fakeBacklog{backlog: store.Backlog{Runs: 3, OldestAge: 90 * time.Second}}
	want := `
# HELP vulnmanager_processing_backlog_scrape_failures_total Scrapes where the unprocessed import runs could not be read from the database.
# TYPE vulnmanager_processing_backlog_scrape_failures_total counter
vulnmanager_processing_backlog_scrape_failures_total 0
# HELP vulnmanager_processing_oldest_unprocessed_run_age_seconds Age of the oldest completed import run that processing has not handled.
# TYPE vulnmanager_processing_oldest_unprocessed_run_age_seconds gauge
vulnmanager_processing_oldest_unprocessed_run_age_seconds 90
# HELP vulnmanager_processing_unprocessed_runs Completed import runs not processed yet.
# TYPE vulnmanager_processing_unprocessed_runs gauge
vulnmanager_processing_unprocessed_runs 3
`
	if err := testutil.CollectAndCompare(NewBacklogCollector(source), strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
}

func TestBacklogCollectorDatabaseErrorDoesNotBreakTheScrape(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(NewBacklogCollector(fakeBacklog{err: errors.New("db down")}))
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather must succeed while the database is down: %v", err)
	}
	if len(families) != 1 || families[0].GetName() != "vulnmanager_processing_backlog_scrape_failures_total" ||
		families[0].GetMetric()[0].GetCounter().GetValue() != 1 {
		t.Fatalf("want only the failure counter set to 1, got %v", families)
	}
}
