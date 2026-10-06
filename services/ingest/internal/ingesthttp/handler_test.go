package ingesthttp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/ingest/gen/api"
	"vulnmanager/services/ingest/internal/jobs"
)

type fakeAuth struct{}

func (fakeAuth) Tenant(_ context.Context, token string) (model.TenantID, error) {
	if token != "good" {
		return "", ErrUnauthorized
	}
	return "acme", nil
}

type fakeIntake struct {
	limit    int64
	accepted jobs.Accepted
	got      jobs.Report
	calls    int
}

func (f *fakeIntake) MaxReportBytes(context.Context, model.TenantID) (int64, error) {
	return f.limit, nil
}

func (f *fakeIntake) Accept(_ context.Context, r jobs.Report) (jobs.Accepted, error) {
	f.calls++
	f.got = r
	return f.accepted, nil
}

func newServer(intake *fakeIntake) http.Handler {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := New(intake, func() model.ScanID { return "generated" }, log)
	return api.HandlerWithOptions(h, api.StdHTTPServerOptions{
		Middlewares: []api.MiddlewareFunc{Auth(fakeAuth{}, log)},
	})
}

func post(srv http.Handler, headers map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reports", strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func validHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer good", "X-Tool": "trivy", "X-Scope": "payments/prod"}
}

func TestIngestReport_Rejections(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(map[string]string)
		body       string
		wantStatus int
	}{
		{name: "no token", mutate: func(h map[string]string) { delete(h, "Authorization") }, body: "r", wantStatus: http.StatusUnauthorized},
		{name: "bad token", mutate: func(h map[string]string) { h["Authorization"] = "Bearer bad" }, body: "r", wantStatus: http.StatusUnauthorized},
		{name: "missing tool", mutate: func(h map[string]string) { delete(h, "X-Tool") }, body: "r", wantStatus: http.StatusBadRequest},
		{name: "empty product", mutate: func(h map[string]string) { h["X-Scope"] = "/ctx" }, body: "r", wantStatus: http.StatusBadRequest},
		{name: "empty body", mutate: func(map[string]string) {}, body: "", wantStatus: http.StatusBadRequest},
		{name: "body above limit", mutate: func(map[string]string) {}, body: "123456", wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			intake := &fakeIntake{limit: 5}
			headers := validHeaders()
			tc.mutate(headers)

			rec := post(newServer(intake), headers, tc.body)

			if rec.Code != tc.wantStatus {
				t.Fatalf("got status %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body)
			}
			if intake.calls != 0 {
				t.Fatalf("intake called %d times, want 0", intake.calls)
			}
		})
	}
}

func TestIngestReport_Accepted(t *testing.T) {
	intake := &fakeIntake{limit: 100, accepted: jobs.Accepted{ScanID: "stored-scan", SHA256: "abc"}}

	rec := post(newServer(intake), validHeaders(), "report")

	if rec.Code != http.StatusAccepted {
		t.Fatalf("got status %d, want 202: %s", rec.Code, rec.Body)
	}
	var resp api.ReportAccepted
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ScanId != "stored-scan" || resp.Sha256 != "abc" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if intake.got.Scope.TenantID != "acme" || intake.got.Scope.ProductID != "payments" || intake.got.Scope.ContextID != "prod" {
		t.Fatalf("unexpected scope: %+v", intake.got.Scope)
	}
	if intake.got.ScanID != "generated" || intake.got.Tool != "trivy" || string(intake.got.Body) != "report" {
		t.Fatalf("unexpected report: %+v", intake.got)
	}
}

func TestIngestReport_ClientScanID(t *testing.T) {
	intake := &fakeIntake{limit: 100}
	headers := validHeaders()
	headers["X-Scan-Id"] = "client-scan"

	post(newServer(intake), headers, "report")

	if intake.got.ScanID != "client-scan" {
		t.Fatalf("got scan id %q, want client-scan", intake.got.ScanID)
	}
}
