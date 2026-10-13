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
		"NORMALIZE_DATABASE_URL":  "postgres://x",
		"NORMALIZE_S3_ENDPOINT":   "garage:3900",
		"NORMALIZE_S3_ACCESS_KEY": "key",
		"NORMALIZE_S3_SECRET_KEY": "secret",
		"NORMALIZE_S3_BUCKET":     "raw",
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	cfg, err := Load(env(validEnv()))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Addr != ":8081" || cfg.WorkerID != "normalize" || cfg.Lease != 5*time.Minute || cfg.MaxAttempts != 5 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoad_WorkerIDFallsBackToHostname(t *testing.T) {
	values := validEnv()
	values["HOSTNAME"] = "pod-1"

	cfg, err := Load(env(values))
	if err != nil || cfg.WorkerID != "pod-1" {
		t.Fatalf("worker id = %q, err = %v", cfg.WorkerID, err)
	}
}

func TestLoad_ReadsOverrides(t *testing.T) {
	values := validEnv()
	values["NORMALIZE_POLL_INTERVAL"] = "500ms"
	values["NORMALIZE_MAX_ATTEMPTS"] = "7"
	values["NORMALIZE_S3_SSL"] = "true"

	cfg, err := Load(env(values))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.PollInterval != 500*time.Millisecond || cfg.MaxAttempts != 7 || !cfg.S3SSL {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoad_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string
	}{
		{"database url missing", func(m map[string]string) { delete(m, "NORMALIZE_DATABASE_URL") }, "NORMALIZE_DATABASE_URL"},
		{"bucket missing", func(m map[string]string) { delete(m, "NORMALIZE_S3_BUCKET") }, "NORMALIZE_S3_BUCKET"},
		{"bad duration", func(m map[string]string) { m["NORMALIZE_LEASE"] = "soon" }, "NORMALIZE_LEASE"},
		{"non-positive duration", func(m map[string]string) { m["NORMALIZE_RETRY_DELAY"] = "-1s" }, "NORMALIZE_RETRY_DELAY"},
		{"bad attempts", func(m map[string]string) { m["NORMALIZE_MAX_ATTEMPTS"] = "0" }, "NORMALIZE_MAX_ATTEMPTS"},
		{"bad ssl flag", func(m map[string]string) { m["NORMALIZE_S3_SSL"] = "maybe" }, "NORMALIZE_S3_SSL"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			values := validEnv()
			tc.mutate(values)

			_, err := Load(env(values))

			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
