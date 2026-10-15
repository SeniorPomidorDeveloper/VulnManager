package config

import (
	"strings"
	"testing"
	"time"
)

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func validEnv() map[string]string {
	return map[string]string{
		"PROCESSING_DATABASE_URL": "postgres://x",
		"PROCESSING_AMQP_URL":     "amqp://guest:guest@rabbit:5672/",
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(env(validEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":8082" || cfg.Prefetch != 4 || cfg.RetryDelay != time.Minute || cfg.WorkerID != "processing" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.AMQPExchange != "vulnmanager.import.completed" || cfg.AMQPQueue != "vulnmanager.processing.import_completed" {
		t.Fatalf("unexpected topology defaults: %+v", cfg)
	}
}

func TestLoadRequiresConnections(t *testing.T) {
	_, err := Load(env(nil))
	if err == nil || !strings.Contains(err.Error(), "PROCESSING_DATABASE_URL") || !strings.Contains(err.Error(), "PROCESSING_AMQP_URL") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadRejectsInvalidNumbers(t *testing.T) {
	for name, value := range map[string]string{
		"PROCESSING_PREFETCH":    "0",
		"PROCESSING_RETRY_DELAY": "-1s",
	} {
		t.Run(name, func(t *testing.T) {
			values := validEnv()
			values[name] = value
			if _, err := Load(env(values)); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestLoadWorkerIDFallsBackToHostname(t *testing.T) {
	values := validEnv()
	values["HOSTNAME"] = "pod-1"
	cfg, err := Load(env(values))
	if err != nil || cfg.WorkerID != "pod-1" {
		t.Fatalf("got %+v, %v", cfg, err)
	}
}
