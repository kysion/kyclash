package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/kysion/kyclash/network-sidecar/internal/productionpeer"
)

var ErrLiveRuntimeUnavailable = errors.New("Linux peer live runtime is not implemented")

func runCheck(arguments []string, config io.Reader, stdout io.Writer) error {
	if len(arguments) != 1 || arguments[0] != "--check-config" {
		return ErrLiveRuntimeUnavailable
	}
	if _, err := productionpeer.DecodeConfig(config); err != nil {
		return productionpeer.ErrInvalidConfig
	}
	_, err := fmt.Fprintln(stdout, "KYCLASH_LINUX_PEER_CONFIG_OK")
	return err
}
