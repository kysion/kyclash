//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/kysion/kyclash/network-sidecar/internal/productionpeer"
)

func execute(arguments []string, stdout, stderr *os.File) int {
	if len(arguments) != 1 || arguments[0] != "--check-config" {
		_, _ = fmt.Fprintln(stderr, "KyClash Linux peer runtime is not available")
		return 1
	}
	encoded, err := productionpeer.ReadLinuxConfig()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "KyClash Linux peer configuration refused")
		return 1
	}
	defer clear(encoded)
	if err := runCheck(arguments, bytes.NewReader(encoded), stdout); err != nil {
		_, _ = fmt.Fprintln(stderr, "KyClash Linux peer configuration refused")
		return 1
	}
	return 0
}

func main() {
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr))
}
