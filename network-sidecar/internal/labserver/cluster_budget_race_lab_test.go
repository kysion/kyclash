//go:build race && kyclash_race_lab

package labserver

import "time"

// The race detector can serialize enough WireGuard and TLS work on a low-CPU
// hosted runner that wall-clock scheduling, rather than the code under test,
// consumes the ordinary bounds. These allowances apply only to the explicitly
// tagged race-lab binary; all lifecycle and reachability assertions remain.
const (
	clusterSingleHealthTimeout     = 25 * time.Second
	clusterCarrierMatrixTimeout    = 45 * time.Second
	clusterFailureLifecycleTimeout = 15 * time.Second
	clusterFailureObservationBound = 3 * time.Second
)
