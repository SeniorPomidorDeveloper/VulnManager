package config

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"vulnmanager/services/normalize/internal/consumer"
	"vulnmanager/services/normalize/internal/queue"
	"vulnmanager/services/normalize/internal/rawread"
)

const (
	defaultAddr        = ":8081"
	defaultWorkerID    = "normalize"
	defaultLease       = 5 * time.Minute
	defaultRetryDelay  = time.Minute
	defaultMaxAttempts = 5
	defaultPrefetch    = 4
	defaultExchange    = "vulnmanager.report.received"
	defaultQueue       = "vulnmanager.normalize.report_received"
)

type Config struct {
	Addr        string
	DatabaseURL string
	WorkerID    queue.WorkerID

	S3Endpoint  rawread.Endpoint
	S3AccessKey rawread.AccessKeyID
	S3SecretKey rawread.SecretAccessKey
	S3Bucket    rawread.Bucket
	S3SSL       bool

	AMQPURL      consumer.URL
	AMQPExchange consumer.ExchangeName
	AMQPQueue    consumer.QueueName
	Prefetch     int

	Lease       time.Duration
	RetryDelay  time.Duration
	MaxAttempts int
}

func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Addr:        withDefault(getenv("NORMALIZE_ADDR"), defaultAddr),
		DatabaseURL: getenv("NORMALIZE_DATABASE_URL"),
		WorkerID:    queue.WorkerID(withDefault(getenv("NORMALIZE_WORKER_ID"), withDefault(getenv("HOSTNAME"), defaultWorkerID))),
		S3Endpoint:  rawread.Endpoint(getenv("NORMALIZE_S3_ENDPOINT")),
		S3AccessKey: rawread.AccessKeyID(getenv("NORMALIZE_S3_ACCESS_KEY")),
		S3SecretKey: rawread.SecretAccessKey(getenv("NORMALIZE_S3_SECRET_KEY")),
		S3Bucket:    rawread.Bucket(getenv("NORMALIZE_S3_BUCKET")),
		MaxAttempts: defaultMaxAttempts,
		Prefetch:    defaultPrefetch,

		AMQPURL:      consumer.URL(getenv("NORMALIZE_AMQP_URL")),
		AMQPExchange: consumer.ExchangeName(withDefault(getenv("NORMALIZE_AMQP_EXCHANGE"), defaultExchange)),
		AMQPQueue:    consumer.QueueName(withDefault(getenv("NORMALIZE_AMQP_QUEUE"), defaultQueue)),
	}

	errs := requireAll(map[string]string{
		"NORMALIZE_DATABASE_URL":  cfg.DatabaseURL,
		"NORMALIZE_S3_ENDPOINT":   string(cfg.S3Endpoint),
		"NORMALIZE_S3_ACCESS_KEY": string(cfg.S3AccessKey),
		"NORMALIZE_S3_SECRET_KEY": string(cfg.S3SecretKey),
		"NORMALIZE_S3_BUCKET":     string(cfg.S3Bucket),
		"NORMALIZE_AMQP_URL":      string(cfg.AMQPURL),
	})

	for _, field := range []struct {
		name     string
		fallback time.Duration
		target   *time.Duration
	}{
		{"NORMALIZE_LEASE", defaultLease, &cfg.Lease},
		{"NORMALIZE_RETRY_DELAY", defaultRetryDelay, &cfg.RetryDelay},
	} {
		value, err := parseDuration(getenv(field.name), field.fallback)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", field.name, err))
		}
		*field.target = value
	}

	if raw := getenv("NORMALIZE_MAX_ATTEMPTS"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			errs = append(errs, fmt.Errorf("NORMALIZE_MAX_ATTEMPTS: want a positive integer, got %q", raw))
		}
		cfg.MaxAttempts = value
	}
	if raw := getenv("NORMALIZE_PREFETCH"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			errs = append(errs, fmt.Errorf("NORMALIZE_PREFETCH: want a positive integer, got %q", raw))
		}
		cfg.Prefetch = value
	}
	if raw := getenv("NORMALIZE_S3_SSL"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("NORMALIZE_S3_SSL: %w", err))
		}
		cfg.S3SSL = value
	}

	return cfg, errors.Join(errs...)
}

func requireAll(values map[string]string) []error {
	var errs []error
	for name, value := range values {
		if value == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	return errs
}

func parseDuration(raw string, fallback time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback, err
	}
	if value <= 0 {
		return fallback, fmt.Errorf("want a positive duration, got %q", raw)
	}
	return value, nil
}

func withDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
