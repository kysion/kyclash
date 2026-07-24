package main

import (
	"fmt"
	"os"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeergueststaging"
)

func run(arguments []string) error {
	result, err := externalpeergueststaging.Run(
		externalpeergueststaging.PeerRole,
		externalpeergueststaging.LayerBPrepare,
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
		fmt.Fprintln(os.Stderr, "external-peer peer Layer-B review preparation refused")
		os.Exit(1)
	}
}
