package pps

import (
	"strings"
	"testing"
)

func TestNormalizeConfigRaisesPPSMinimumAndAddsDefaults(t *testing.T) {
	got := normalizeConfig("PPS_LIMIT=10000\nPPS_SINGLE_TARGET_LIMIT=15000\nBRIDGE_NAME=incusbr0\n")

	for _, expected := range []string{
		"PPS_LIMIT=20000",
		"PPS_SINGLE_TARGET_LIMIT=20000",
		"PPS_MIN_LIMIT=20000",
		"PPS_OBSERVE_SECONDS=120",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("normalized config does not contain %q: %q", expected, got)
		}
	}
}

func TestNormalizeConfigPreservesHigherLimits(t *testing.T) {
	got := normalizeConfig("PPS_LIMIT=50000\nPPS_SINGLE_TARGET_LIMIT=30000\nPPS_OBSERVE_SECONDS=60\n")

	for _, expected := range []string{
		"PPS_LIMIT=50000",
		"PPS_SINGLE_TARGET_LIMIT=30000",
		"PPS_OBSERVE_SECONDS=60",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("normalized config does not preserve %q: %q", expected, got)
		}
	}
}
