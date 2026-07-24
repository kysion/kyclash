package main

import (
	"fmt"
	"os"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeergueststaging"
)

func run(arguments []string) error {
	result, err := externalpeergueststaging.Run(
		externalpeergueststaging.PeerRole,
		externalpeergueststaging.LayerASSHBootstrap,
		arguments,
	)
	if err != nil {
		return err
	}
	externalpeergueststaging.PrintResult(result)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "peer SSH bootstrap refused")
		os.Exit(1)
	}
}
