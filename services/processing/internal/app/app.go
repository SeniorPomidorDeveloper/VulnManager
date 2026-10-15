package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"vulnmanager/services/processing/internal/adapters"
	"vulnmanager/services/processing/internal/config"
	"vulnmanager/services/processing/internal/consumer"
	"vulnmanager/services/processing/internal/store"
	"vulnmanager/services/processing/internal/worker"
)

const (
	shutdownTimeout   = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
)

func Run(log *slog.Logger) error {
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

	registry, err := adapters.Builtin()
	if err != nil {
		return fmt.Errorf("adapters: %w", err)
	}
	w, err := worker.New(store.New(pool), registry)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	srv := &http.Server{Addr: cfg.Addr, Handler: newMux(reg), ReadHeaderTimeout: readHeaderTimeout}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	var consuming sync.WaitGroup
	consuming.Add(1)
	go func() {
		defer consuming.Done()
		consumer.New(consumer.Config{
			URL:         cfg.AMQPURL,
			Exchange:    cfg.AMQPExchange,
			Queue:       cfg.AMQPQueue,
			Prefetch:    cfg.Prefetch,
			RetryDelay:  cfg.RetryDelay,
			ConsumerTag: cfg.WorkerID,
		}, handler{worker: w, log: log}, consumer.NewMetrics(reg), log).Run(ctx)
	}()

	log.Info("processing started", "addr", cfg.Addr, "worker", cfg.WorkerID)

	select {
	case err := <-errCh:
		stop()
		consuming.Wait()
		return err
	case <-ctx.Done():
	}

	consuming.Wait()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

func newMux(reg *prometheus.Registry) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	return mux
}
