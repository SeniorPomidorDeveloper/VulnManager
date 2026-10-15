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

	"vulnmanager/services/normalize/gen/db"
	"vulnmanager/services/normalize/internal/adapters"
	"vulnmanager/services/normalize/internal/config"
	"vulnmanager/services/normalize/internal/consumer"
	"vulnmanager/services/normalize/internal/metrics"
	"vulnmanager/services/normalize/internal/queue"
	"vulnmanager/services/normalize/internal/rawread"
	"vulnmanager/services/normalize/internal/store"
	"vulnmanager/services/normalize/internal/worker"
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

	w, reg, err := newWorker(cfg, pool, log)
	if err != nil {
		return err
	}

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
			ConsumerTag: string(cfg.WorkerID),
		}, w, consumer.NewMetrics(reg), log).Run(ctx)
	}()

	log.Info("normalize started", "addr", cfg.Addr, "worker", cfg.WorkerID)

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

func newWorker(cfg config.Config, pool *pgxpool.Pool, log *slog.Logger) (*worker.Worker, *prometheus.Registry, error) {
	raw, err := rawread.NewS3Reader(rawread.S3Config{
		Endpoint:        cfg.S3Endpoint,
		AccessKeyID:     cfg.S3AccessKey,
		SecretAccessKey: cfg.S3SecretKey,
		UseSSL:          cfg.S3SSL,
		Bucket:          cfg.S3Bucket,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("rawstore: %w", err)
	}

	registry, err := adapters.Builtin()
	if err != nil {
		return nil, nil, fmt.Errorf("adapters: %w", err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := metrics.New(reg)
	findingStore := store.New(pool)
	reg.MustRegister(metrics.NewBacklogCollector(findingStore))

	w, err := worker.New(
		worker.Config{
			ID:          cfg.WorkerID,
			Lease:       cfg.Lease,
			RetryDelay:  cfg.RetryDelay,
			MaxAttempts: cfg.MaxAttempts,
		},
		worker.Deps{
			Jobs:     m.WrapJobs(queue.New(db.New(pool)), time.Now),
			Raw:      raw,
			Store:    m.WrapStore(worker.NewStore(findingStore)),
			Adapters: registry,
			Clock:    time.Now,
			Log:      log,
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("worker: %w", err)
	}
	return w, reg, nil
}

func newMux(reg *prometheus.Registry) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	return mux
}
