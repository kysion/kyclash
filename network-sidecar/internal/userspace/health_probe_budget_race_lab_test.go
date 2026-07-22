//go:build race && kyclash_race_lab

package userspace

import (
	"testing"
	"time"
)

func TestRaceLabHealthProbeBudgetIsIsolated(t *testing.T) {
	if healthProbeTimeout != 2*time.Second {
		t.Fatalf("race-lab health probe budget changed: %v", healthProbeTimeout)
	}
}
