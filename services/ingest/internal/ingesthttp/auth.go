package ingesthttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"vulnmanager/modules/model"
	"vulnmanager/services/ingest/gen/api"
)

var ErrUnauthorized = errors.New("ingesthttp: unauthorized")

type Authenticator interface {
	Tenant(ctx context.Context, token string) (model.TenantID, error)
}

type tenantKey struct{}

func Auth(auth Authenticator, log *slog.Logger) api.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r)
			if !ok {
				fail(w, log, unauthorized("bearer token is required"))
				return
			}
			tenantID, err := auth.Tenant(r.Context(), token)
			if errors.Is(err, ErrUnauthorized) {
				fail(w, log, unauthorized("token is not valid"))
				return
			}
			if err != nil {
				fail(w, log, internal("authenticate", err))
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tenantKey{}, tenantID)))
		})
	}
}

func tenantFrom(ctx context.Context) (model.TenantID, bool) {
	tenantID, ok := ctx.Value(tenantKey{}).(model.TenantID)
	return tenantID, ok
}

func bearerToken(r *http.Request) (string, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return token, ok && token != ""
}
