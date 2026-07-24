package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "peer root supervisor accepts no arguments")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()
	if err := externalpeer.RunPeerRootSupervisor(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "peer root supervisor failed")
		os.Exit(1)
	}
}
