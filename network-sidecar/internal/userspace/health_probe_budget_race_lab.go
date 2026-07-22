//go:build race && kyclash_race_lab

package userspace

import "time"

// Race instrumentation on the three-core hosted macOS runner can delay an
// otherwise healthy loopback ping/pong beyond the shipped one-second budget.
// This test-only tag preserves the same health path and five-run race coverage
// without changing the deadline in ordinary or release builds. Requiring the
// automatically supplied `race` tag makes accidental non-race use fail closed.
const healthProbeTimeout = 2 * time.Second
