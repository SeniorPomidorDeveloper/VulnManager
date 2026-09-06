//go:build integration

package rawstore_test

import (
	"os"
	"testing"

	"vulnmanager/modules/rawstore"
	"vulnmanager/modules/rawstore/rawstoretest"
)

func TestS3Store_ContractSuite(t *testing.T) {
	cfg := rawstore.S3Config{
		Endpoint:        envOr("RAWSTORE_TEST_S3_ENDPOINT", "localhost:9000"),
		AccessKeyID:     envOr("RAWSTORE_TEST_S3_ACCESS_KEY", "vulnmanager"),
		SecretAccessKey: envOr("RAWSTORE_TEST_S3_SECRET_KEY", "vulnmanager-local-dev"),
		Bucket:          envOr("RAWSTORE_TEST_S3_BUCKET", "vulnmanager-raw"),
		UseSSL:          false,
	}

	rawstoretest.RunContractSuite(t, func() rawstore.Store {
		s, err := rawstore.NewS3Store(cfg)
		if err != nil {
			t.Fatalf("NewS3Store: %v", err)
		}
		return s
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
