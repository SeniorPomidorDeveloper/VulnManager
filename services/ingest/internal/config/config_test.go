package config

import (
	"strings"
	"testing"
)

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestLoad(t *testing.T) {
	s3 := map[string]string{
		"INGEST_DATABASE_URL":  "postgres://x",
		"INGEST_TENANT":        "acme",
		"INGEST_S3_ENDPOINT":   "minio:9000",
		"INGEST_S3_ACCESS_KEY": "key",
		"INGEST_S3_SECRET_KEY": "secret",
		"INGEST_S3_BUCKET":     "raw",
		"INGEST_AMQP_URL":      "amqp://guest:guest@rabbit:5672/",
	}
	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string
	}{
		{name: "s3 profile", mutate: func(map[string]string) {}},
		{name: "pg profile needs no s3", mutate: func(m map[string]string) {
			m["INGEST_RAWSTORE"] = "pg"
			delete(m, "INGEST_S3_ENDPOINT")
		}},
		{name: "database url missing", mutate: func(m map[string]string) { delete(m, "INGEST_DATABASE_URL") }, wantErr: "INGEST_DATABASE_URL"},
		{name: "tenant missing", mutate: func(m map[string]string) { delete(m, "INGEST_TENANT") }, wantErr: "INGEST_TENANT"},
		{name: "s3 bucket missing", mutate: func(m map[string]string) { delete(m, "INGEST_S3_BUCKET") }, wantErr: "INGEST_S3_BUCKET"},
		{name: "unknown profile", mutate: func(m map[string]string) { m["INGEST_RAWSTORE"] = "mongo" }, wantErr: "unknown profile"},
		{name: "events none needs no broker", mutate: func(m map[string]string) {
			m["INGEST_EVENTS"] = "none"
			delete(m, "INGEST_AMQP_URL")
		}},
		{name: "amqp url missing", mutate: func(m map[string]string) { delete(m, "INGEST_AMQP_URL") }, wantErr: "INGEST_AMQP_URL"},
		{name: "unknown events mode", mutate: func(m map[string]string) { m["INGEST_EVENTS"] = "kafka" }, wantErr: "INGEST_EVENTS"},
		{name: "bad ssl flag", mutate: func(m map[string]string) { m["INGEST_S3_SSL"] = "maybe" }, wantErr: "INGEST_S3_SSL"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]string{}
			for k, v := range s3 {
				values[k] = v
			}
			tc.mutate(values)

			cfg, err := Load(env(values))

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if cfg.Addr != ":8080" {
					t.Fatalf("got addr %q, want default :8080", cfg.Addr)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got err=%v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
