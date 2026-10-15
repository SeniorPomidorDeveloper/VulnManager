package config

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"vulnmanager/services/processing/internal/consumer"
)

const (
	defaultAddr       = ":8082"
	defaultWorkerID   = "processing"
	defaultRetryDelay = time.Minute
	defaultPrefetch   = 4
	defaultExchange   = "vulnmanager.import.completed"
	defaultQueue      = "vulnmanager.processing.import_completed"
)

type Config struct {
	Addr        string
	DatabaseURL string
	WorkerID    string

	AMQPURL      consumer.URL
	AMQPExchange consumer.ExchangeName
	AMQPQueue    consumer.QueueName
	Prefetch     int
	RetryDelay   time.Duration
}

func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Addr:        withDefault(getenv("PROCESSING_ADDR"), defaultAddr),
		DatabaseURL: getenv("PROCESSING_DATABASE_URL"),
		WorkerID:    withDefault(getenv("PROCESSING_WORKER_ID"), withDefault(getenv("HOSTNAME"), defaultWorkerID)),
		Prefetch:    defaultPrefetch,
		RetryDelay:  defaultRetryDelay,

		AMQPURL:      consumer.URL(getenv("PROCESSING_AMQP_URL")),
		AMQPExchange: consumer.ExchangeName(withDefault(getenv("PROCESSING_AMQP_EXCHANGE"), defaultExchange)),
		AMQPQueue:    consumer.QueueName(withDefault(getenv("PROCESSING_AMQP_QUEUE"), defaultQueue)),
	}

	var errs []error
	for name, value := range map[string]string{
		"PROCESSING_DATABASE_URL": cfg.DatabaseURL,
		"PROCESSING_AMQP_URL":     string(cfg.AMQPURL),
	} {
		if value == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}

	if raw := getenv("PROCESSING_PREFETCH"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			errs = append(errs, fmt.Errorf("PROCESSING_PREFETCH: want a positive integer, got %q", raw))
		}
		cfg.Prefetch = value
	}
	if raw := getenv("PROCESSING_RETRY_DELAY"); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value <= 0 {
			errs = append(errs, fmt.Errorf("PROCESSING_RETRY_DELAY: want a positive duration, got %q", raw))
		}
		cfg.RetryDelay = value
	}

	return cfg, errors.Join(errs...)
}

func withDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
