package model

import "testing"

func TestSeverity_RankOrdersFromInfoToCritical(t *testing.T) {
	ordered := []Severity{SeverityInfo, SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].Rank() >= ordered[i].Rank() {
			t.Fatalf("%v (rank %d) must rank below %v (rank %d)", ordered[i-1], ordered[i-1].Rank(), ordered[i], ordered[i].Rank())
		}
	}
}

func TestSeverity_ZeroValueIsUnknownRank(t *testing.T) {
	var zero Severity
	if zero.Rank() != SeverityUnknown.Rank() {
		t.Fatalf("zero severity rank %d, want %d", zero.Rank(), SeverityUnknown.Rank())
	}
}
