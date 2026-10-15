package fptest

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/fingerprint"
)

func RunContractSuite(t *testing.T, strategy fingerprint.Strategy, applicable model.Finding) {
	t.Helper()

	t.Run("declares identity", func(t *testing.T) {
		if strategy.ID() == "" || strategy.Level() == "" || strategy.Version() < 1 {
			t.Fatalf("incomplete declaration: id=%q level=%q version=%d", strategy.ID(), strategy.Level(), strategy.Version())
		}
	})

	t.Run("skips empty finding", func(t *testing.T) {
		if _, ok := strategy.Fingerprint(model.Finding{}); ok {
			t.Fatal("empty finding must not produce a fingerprint")
		}
	})

	got, ok := strategy.Fingerprint(applicable)
	if !ok {
		t.Fatal("applicable finding produced no fingerprint")
	}

	t.Run("value carries version and level", func(t *testing.T) {
		prefix := fmt.Sprintf("v%d:%s:sha256:", strategy.Version(), strategy.Level())
		if got.Level != strategy.Level() || !strings.HasPrefix(string(got.Value), prefix) {
			t.Fatalf("got %+v, want prefix %q", got, prefix)
		}
	})

	t.Run("is deterministic", func(t *testing.T) {
		for range 10 {
			again, _ := strategy.Fingerprint(applicable)
			if again != got {
				t.Fatalf("got %+v, want %+v", again, got)
			}
		}
	})

	t.Run("ignores fields outside identity", func(t *testing.T) {
		noisy := applicable
		noisy.ID = "other-id"
		noisy.ImportRunID = "other-run"
		noisy.Title = "other title"
		noisy.Description = "other description"
		noisy.Severity = model.SeverityInfo
		noisy.Raw = []byte(`{"noise":true}`)
		noisy.DetectedAt = time.Unix(1, 0)
		noisy.AlgoVersion = "other"
		noisy.Diagnostics = noisy.Diagnostics.Append(model.DiagLevelWarn, "noise", "noise")
		again, ok := strategy.Fingerprint(noisy)
		if !ok || again != got {
			t.Fatalf("got %+v (%v), want %+v", again, ok, got)
		}
	})
}
