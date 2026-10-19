package ingesthttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"vulnmanager/modules/model"
	"vulnmanager/services/ingest/gen/api"
	"vulnmanager/services/ingest/internal/jobs"
)

var toolNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type Intake interface {
	MaxReportBytes(ctx context.Context, tenantID model.TenantID) (int64, error)
	Accept(ctx context.Context, r jobs.Report) (jobs.Accepted, error)
}

type Handler struct {
	intake    Intake
	newScanID func() model.ScanID
	log       *slog.Logger
}

func New(intake Intake, newScanID func() model.ScanID, log *slog.Logger) *Handler {
	return &Handler{intake: intake, newScanID: newScanID, log: log}
}

type problem struct {
	status int
	code   string
	detail string
	op     string
	cause  error
}

func badRequest(detail string) *problem {
	return &problem{status: http.StatusBadRequest, code: "bad_request", detail: detail}
}

func unauthorized(detail string) *problem {
	return &problem{status: http.StatusUnauthorized, code: "unauthorized", detail: detail}
}

func tooLarge() *problem {
	return &problem{status: http.StatusRequestEntityTooLarge, code: "report_too_large", detail: "report exceeds tenant limit"}
}

func notPublished(err error) *problem {
	return &problem{status: http.StatusServiceUnavailable, code: "event_not_published", detail: "report is stored but processing event was not delivered, retry the request", op: "publish event", cause: err}
}

func internal(op string, err error) *problem {
	return &problem{status: http.StatusInternalServerError, code: "internal", detail: "internal error", op: op, cause: err}
}

func (h *Handler) IngestReport(w http.ResponseWriter, r *http.Request, params api.IngestReportParams) {
	ctx := r.Context()

	tenantID, ok := tenantFrom(ctx)
	if !ok {
		fail(w, h.log, internal("tenant from context", errors.New("auth middleware is not installed")))
		return
	}
	scope, p := parseScope(tenantID, params.XScope)
	if p != nil {
		fail(w, h.log, p)
		return
	}
	tool, p := parseTool(params.XTool)
	if p != nil {
		fail(w, h.log, p)
		return
	}
	body, p := h.readBody(ctx, w, r, tenantID)
	if p != nil {
		fail(w, h.log, p)
		return
	}
	accepted, p := h.accept(ctx, jobs.Report{
		Scope:  scope,
		Tool:   tool,
		ScanID: h.scanID(params.XScanId),
		Body:   body,
	})
	if p != nil {
		fail(w, h.log, p)
		return
	}

	writeJSON(w, h.log, http.StatusAccepted, "application/json", api.ReportAccepted{
		ScanId: string(accepted.ScanID),
		Sha256: accepted.SHA256,
	})
}

func (h *Handler) readBody(ctx context.Context, w http.ResponseWriter, r *http.Request, tenantID model.TenantID) ([]byte, *problem) {
	limit, err := h.intake.MaxReportBytes(ctx, tenantID)
	if errors.Is(err, jobs.ErrTenantNotFound) {
		return nil, unauthorized("tenant is not registered")
	}
	if err != nil {
		return nil, internal("tenant limit", err)
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	var exceeded *http.MaxBytesError
	if errors.As(err, &exceeded) {
		return nil, tooLarge()
	}
	if err != nil {
		return nil, badRequest("cannot read request body")
	}
	if len(body) == 0 {
		return nil, badRequest("report body is empty")
	}
	return body, nil
}

func (h *Handler) accept(ctx context.Context, report jobs.Report) (jobs.Accepted, *problem) {
	accepted, err := h.intake.Accept(ctx, report)
	if errors.Is(err, jobs.ErrReportTooLarge) {
		return jobs.Accepted{}, tooLarge()
	}
	if errors.Is(err, jobs.ErrNotPublished) {
		return jobs.Accepted{}, notPublished(err)
	}
	if err != nil {
		return jobs.Accepted{}, internal("accept report", err)
	}
	return accepted, nil
}

func (h *Handler) scanID(header *string) model.ScanID {
	if header != nil && *header != "" {
		return model.ScanID(*header)
	}
	return h.newScanID()
}

func fail(w http.ResponseWriter, log *slog.Logger, p *problem) {
	if p.cause != nil {
		log.Error("ingest failed", "op", p.op, "error", p.cause)
	}
	writeProblem(w, log, p.status, p.code, p.detail)
}

func parseScope(tenantID model.TenantID, header string) (model.Scope, *problem) {
	product, contextID, _ := strings.Cut(header, "/")
	scope, err := model.NewScope(tenantID, model.ProductID(product), model.ContextID(contextID))
	if err != nil {
		return model.Scope{}, badRequest(err.Error())
	}
	return scope, nil
}

func parseTool(header string) (model.ToolName, *problem) {
	if !toolNamePattern.MatchString(header) {
		return "", badRequest("X-Tool must match " + toolNamePattern.String())
	}
	return model.ToolName(header), nil
}

func writeProblem(w http.ResponseWriter, log *slog.Logger, status int, code, detail string) {
	writeJSON(w, log, status, "application/problem+json", api.Problem{
		Type:   code,
		Title:  http.StatusText(status),
		Status: status,
		Detail: &detail,
	})
}

func writeJSON(w http.ResponseWriter, log *slog.Logger, status int, contentType string, v any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Warn("cannot write response", "error", err)
	}
}

func InvalidRequest(log *slog.Logger) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, _ *http.Request, err error) {
		writeProblem(w, log, http.StatusBadRequest, "bad_request", err.Error())
	}
}
