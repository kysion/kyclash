package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "listener auditor accepts no arguments")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	inventory, err := externalpeer.CollectListenerInventory(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listener audit failed")
		os.Exit(1)
	}
	encoded, err := externalpeer.EncodeListenerInventory(inventory)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listener audit encoding failed")
		os.Exit(1)
	}
	defer clear(encoded)
	if _, err := os.Stdout.Write(encoded); err != nil {
		fmt.Fprintln(os.Stderr, "listener audit output failed")
		os.Exit(1)
	}
}
