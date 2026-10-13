package normtest

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
)

func Suite(t *testing.T, n normalizers.Normalizer, findings []model.Finding) {
	t.Helper()

	t.Run("identity", func(t *testing.T) {
		if n.ID() == "" || n.Version() == "" {
			t.Fatalf("empty id %q or version %q", n.ID(), n.Version())
		}
	})

	for _, original := range findings {
		t.Run(string(original.ToolFindingID), func(t *testing.T) {
			if !n.Applies(original.Kind) {
				t.Skip("normalizer does not apply")
			}
			once := apply(t, n, original)
			if again := apply(t, n, original); !reflect.DeepEqual(once, again) {
				t.Fatalf("not deterministic:\nfirst  %+v\nsecond %+v", once, again)
			}
			if twice := apply(t, n, once); !reflect.DeepEqual(once, twice) {
				t.Fatalf("not idempotent:\nonce  %+v\ntwice %+v", once, twice)
			}
		})
	}
}

func apply(t *testing.T, n normalizers.Normalizer, finding model.Finding) model.Finding {
	t.Helper()
	finding.Diagnostics = slices.Clone(finding.Diagnostics)
	if err := n.Normalize(context.Background(), &finding); err != nil {
		t.Fatalf("normalizers: %v", err)
	}
	return finding
}
