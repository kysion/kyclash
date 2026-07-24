package main

import (
	"fmt"
	"os"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "forced command accepts no arguments")
		os.Exit(2)
	}
	if err := externalpeer.RunForcedCommand(os.Getenv("SSH_ORIGINAL_COMMAND"), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "forced command refused")
		os.Exit(1)
	}
}
