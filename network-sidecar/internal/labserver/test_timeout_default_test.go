//go:build !race

package labserver

import "time"

const tunnelProofTimeout = 8 * time.Second
