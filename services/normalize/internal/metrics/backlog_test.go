package metrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"vulnmanager/services/normalize/internal/store"
)

type fakeBacklog struct {
	backlog store.Backlog
	err     error
}

func (f fakeBacklog) Backlog(context.Context) (store.Backlog, error) {
	return f.backlog, f.err
}

func TestBacklogCollector_ExposesCountAndAge(t *testing.T) {
	source := fakeBacklog{backlog: store.Backlog{Runs: 3, OldestAge: 90 * time.Second}}
	want := `
# HELP vulnmanager_normalize_oldest_unpublished_run_age_seconds Age of the oldest completed import run without a published import.completed event.
# TYPE vulnmanager_normalize_oldest_unpublished_run_age_seconds gauge
vulnmanager_normalize_oldest_unpublished_run_age_seconds 90
# HELP vulnmanager_normalize_unpublished_runs Completed import runs whose import.completed event was not published yet.
# TYPE vulnmanager_normalize_unpublished_runs gauge
vulnmanager_normalize_unpublished_runs 3
`
	if err := testutil.CollectAndCompare(NewBacklogCollector(source), strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
}

func TestBacklogCollector_ReportsTheSourceError(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(NewBacklogCollector(fakeBacklog{err: errors.New("db down")}))
	if _, err := reg.Gather(); err == nil {
		t.Fatal("a failing source must surface as a gather error")
	}
}
