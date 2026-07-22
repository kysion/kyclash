//go:build !kyclash_race_lab

package userspace

import "time"

// Keep the shipped health probe deadline strict. The wider budget used by the
// low-CPU race-detector integration matrix is selected only by the explicit
// kyclash_race_lab build tag.
const healthProbeTimeout = time.Second
