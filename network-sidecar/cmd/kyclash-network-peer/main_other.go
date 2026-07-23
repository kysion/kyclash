//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "KyClash Linux peer requires Linux")
	os.Exit(1)
}
