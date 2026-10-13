package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"vulnmanager/modules/model"
	"vulnmanager/services/ingest/gen/api"
	"vulnmanager/services/ingest/internal/config"
	"vulnmanager/services/ingest/internal/events"
	"vulnmanager/services/ingest/internal/ingesthttp"
	"vulnmanager/services/ingest/internal/jobs"
	"vulnmanager/services/ingest/internal/jobs/pgstore"
	"vulnmanager/services/ingest/internal/rawstoreimpl"
)

var version = "dev"

const shutdownTimeout = 10 * time.Second

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "ingest", "version", version)
	if err := run(log); err != nil {
		log.Error("ingest stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()

	raw, err := newRawWriter(cfg, pool)
	if err != nil {
		return fmt.Errorf("rawstore: %w", err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	metrics := ingesthttp.NewMetrics(reg)

	handler := ingesthttp.New(
		jobs.NewEnqueuer(pgstore.New(pool), raw, events.Disabled{}),
		func() model.ScanID { return model.ScanID(uuid.NewString()) },
		log,
	)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	api.HandlerWithOptions(handler, api.StdHTTPServerOptions{
		BaseRouter:       mux,
		ErrorHandlerFunc: ingesthttp.InvalidRequest,
		Middlewares:      []api.MiddlewareFunc{ingesthttp.StaticTenant(model.TenantID(cfg.Tenant))},
	})

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           metrics.Middleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Info("ingest started", "addr", cfg.Addr, "rawstore", cfg.RawStore)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

func newRawWriter(cfg config.Config, pool *pgxpool.Pool) (jobs.RawWriter, error) {
	if cfg.RawStore == config.RawStorePG {
		return rawstoreimpl.NewPGWriter(pool), nil
	}
	return rawstoreimpl.NewS3Writer(rawstoreimpl.S3Config{
		Endpoint:        cfg.S3Endpoint,
		AccessKeyID:     cfg.S3AccessKey,
		SecretAccessKey: cfg.S3SecretKey,
		UseSSL:          cfg.S3SSL,
		Bucket:          cfg.S3Bucket,
	})
}
