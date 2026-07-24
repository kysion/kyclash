//go:build race

package systemlabpeer

import (
	"testing"
	"time"
)

const systemLabTunnelReadinessTimeout = 60 * time.Second

func TestRaceSystemLabTunnelReadinessBudgetIsIsolated(t *testing.T) {
	if systemLabTunnelReadinessTimeout != time.Minute {
		t.Fatalf("race tunnel readiness budget changed: %v", systemLabTunnelReadinessTimeout)
	}
}
