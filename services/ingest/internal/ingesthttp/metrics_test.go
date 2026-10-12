package ingesthttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetrics_CountsByRouteAndCode(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/reports", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	srv := m.Middleware(mux)

	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/reports", nil))
	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/nowhere", nil))

	if got := testutil.ToFloat64(m.requests.WithLabelValues("POST /api/v1/reports", "202")); got != 1 {
		t.Fatalf("got %v accepted requests, want 1", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("unmatched", "404")); got != 1 {
		t.Fatalf("got %v unmatched requests, want 1", got)
	}
}
