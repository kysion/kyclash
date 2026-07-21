//go:build race

package labserver

import "time"

// The race runtime substantially slows the userspace WireGuard handshake on
// shared macOS runners. Keep the ordinary test's fast threshold unchanged.
const tunnelProofTimeout = 20 * time.Second
