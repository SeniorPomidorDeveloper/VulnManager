package config

import (
	"errors"
	"fmt"
	"strconv"
)

const (
	RawStoreS3 = "s3"
	RawStorePG = "pg"

	EventsAMQP = "amqp"
	EventsNone = "none"

	defaultExchange = "vulnmanager.report.received"
)

type Config struct {
	Addr        string
	DatabaseURL string
	Tenant      string
	RawStore    string

	Events       string
	AMQPURL      string
	AMQPExchange string

	S3Endpoint  string
	S3AccessKey string
	S3SecretKey string
	S3Bucket    string
	S3SSL       bool
}

func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Addr:        withDefault(getenv("INGEST_ADDR"), ":8080"),
		DatabaseURL: getenv("INGEST_DATABASE_URL"),
		Tenant:      getenv("INGEST_TENANT"),
		RawStore:    withDefault(getenv("INGEST_RAWSTORE"), RawStoreS3),

		Events:       withDefault(getenv("INGEST_EVENTS"), EventsAMQP),
		AMQPURL:      getenv("INGEST_AMQP_URL"),
		AMQPExchange: withDefault(getenv("INGEST_AMQP_EXCHANGE"), defaultExchange),
		S3Endpoint:   getenv("INGEST_S3_ENDPOINT"),
		S3AccessKey:  getenv("INGEST_S3_ACCESS_KEY"),
		S3SecretKey:  getenv("INGEST_S3_SECRET_KEY"),
		S3Bucket:     getenv("INGEST_S3_BUCKET"),
	}

	var errs []error
	if cfg.DatabaseURL == "" {
		errs = append(errs, errors.New("INGEST_DATABASE_URL is required"))
	}
	if cfg.Tenant == "" {
		errs = append(errs, errors.New("INGEST_TENANT is required"))
	}
	if ssl := getenv("INGEST_S3_SSL"); ssl != "" {
		v, err := strconv.ParseBool(ssl)
		if err != nil {
			errs = append(errs, fmt.Errorf("INGEST_S3_SSL: %w", err))
		}
		cfg.S3SSL = v
	}

	switch cfg.RawStore {
	case RawStorePG:
	case RawStoreS3:
		errs = append(errs, requireS3(cfg)...)
	default:
		errs = append(errs, fmt.Errorf("INGEST_RAWSTORE: unknown profile %q", cfg.RawStore))
	}

	switch cfg.Events {
	case EventsNone:
	case EventsAMQP:
		if cfg.AMQPURL == "" {
			errs = append(errs, errors.New("INGEST_AMQP_URL is required for events amqp"))
		}
	default:
		errs = append(errs, fmt.Errorf("INGEST_EVENTS: unknown mode %q", cfg.Events))
	}

	return cfg, errors.Join(errs...)
}

func requireS3(cfg Config) []error {
	var errs []error
	for name, value := range map[string]string{
		"INGEST_S3_ENDPOINT":   cfg.S3Endpoint,
		"INGEST_S3_ACCESS_KEY": cfg.S3AccessKey,
		"INGEST_S3_SECRET_KEY": cfg.S3SecretKey,
		"INGEST_S3_BUCKET":     cfg.S3Bucket,
	} {
		if value == "" {
			errs = append(errs, fmt.Errorf("%s is required for rawstore %s", name, RawStoreS3))
		}
	}
	return errs
}

func withDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
