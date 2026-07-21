package main

import (
	"context"
	"os"
	"time"
)

const parentWatchInterval = 100 * time.Millisecond

// watchParent cancels the sidecar process boundary when the controller that
// launched it disappears.  A sidecar started directly by launchd/init has
// PPID 1 from the beginning and is intentionally not watched; a sidecar
// launched by KyClash starts with the app/controller PID and detects the
// re-parenting to PID 1 after a hard controller exit.
func watchParent(ctx context.Context, initialParent int, cancel context.CancelFunc) {
	watchParentWith(ctx, initialParent, cancel, os.Getppid)
}

func watchParentWith(ctx context.Context, initialParent int, cancel context.CancelFunc, currentParent func() int) {
	if initialParent <= 1 {
		return
	}
	ticker := time.NewTicker(parentWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if currentParent() != initialParent {
				cancel()
				return
			}
		}
	}
}
