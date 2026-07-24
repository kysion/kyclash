//go:build !race && !kyclash_race_lab

package systemlabpeer

import (
	"testing"
	"time"
)

const systemLabTunnelReadinessTimeout = 20 * time.Second

func TestShippedSystemLabTunnelReadinessBudgetRemainsTwentySeconds(t *testing.T) {
	if systemLabTunnelReadinessTimeout != 20*time.Second {
		t.Fatalf("shipped tunnel readiness budget changed: %v", systemLabTunnelReadinessTimeout)
	}
}
