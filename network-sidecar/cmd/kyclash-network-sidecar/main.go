package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kysion/kyclash/network-sidecar/internal/bootstrap"
)

type handshake struct {
	ProtocolVersion uint8  `json:"protocol_version"`
	InstanceID      string `json:"instance_id"`
	AuthProof       string `json:"auth_proof"`
}

func run(arguments []string, stdin io.Reader, stdout io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("command-line arguments are not accepted")
	}
	reader := bufio.NewReaderSize(stdin, 64*1_024)
	config, err := bootstrap.DecodeLine(reader)
	if err != nil {
		return err
	}
	defer config.Clear()
	response := handshake{
		ProtocolVersion: bootstrap.ProtocolVersion,
		InstanceID:      config.InstanceID,
		AuthProof:       bootstrap.AuthProof(config),
	}
	if err := json.NewEncoder(stdout).Encode(response); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "KyClash network sidecar bootstrap failed")
		os.Exit(1)
	}
}
