//go:build !kyclash_race_lab

package labserver

import "time"

// These are the shipped-behavior integration bounds. Keep them separate from
// the explicitly tagged low-CPU race-lab allowances so an ordinary test run
// continues to enforce the production timing contract.
const (
	clusterSingleHealthTimeout     = 20 * time.Second
	clusterCarrierMatrixTimeout    = 30 * time.Second
	clusterFailureLifecycleTimeout = 10 * time.Second
	clusterFailureObservationBound = 2 * time.Second
)
