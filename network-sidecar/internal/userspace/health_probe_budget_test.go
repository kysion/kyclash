//go:build !kyclash_race_lab

package userspace

import (
	"testing"
	"time"
)

func TestShippedHealthProbeBudgetRemainsOneSecond(t *testing.T) {
	if healthProbeTimeout != time.Second {
		t.Fatalf("shipped health probe budget changed: %v", healthProbeTimeout)
	}
}
