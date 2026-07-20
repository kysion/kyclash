package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kysion/kyclash/network-sidecar/internal/bootstrap"
	"github.com/kysion/kyclash/network-sidecar/internal/ipc"
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
	return ipc.Serve(reader, stdout)
}

func execute(arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if err := run(arguments, stdin, stdout); err != nil {
		// Bootstrap and IPC errors are deliberately not formatted here: decoding
		// errors can retain attacker-controlled input in their chains, and the
		// process boundary must never turn that input into crash diagnostics.
		fmt.Fprintln(stderr, "KyClash network sidecar bootstrap failed")
		return 1
	}
	return 0
}

func main() {
	os.Exit(execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
