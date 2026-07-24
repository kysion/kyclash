package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeerhost"
)

func TestCLIHasOnlyFixedCommandsAndRedactedOutput(t *testing.T) {
	root := t.TempDir()
	moduleRoot := filepath.Join(root, "network-sidecar")
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(moduleRoot, "go.mod"),
		[]byte("module github.com/kysion/kyclash/network-sidecar\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runAt(
		context.Background(),
		keyInitCommand,
		root,
		&output,
		time.Now().UTC(),
		bytes.NewReader(bytes.Repeat([]byte{0x63}, 64)),
	); err != nil {
		t.Fatal(err)
	}
	if output.String() != "courier_key_initialized=true\n" {
		t.Fatalf("unexpected CLI output: %q", output.String())
	}
	for _, command := range []string{
		"",
		"help",
		"key-init=/tmp/key",
		"sign-transaction=/tmp/run",
	} {
		if err := runAt(
			context.Background(),
			command,
			root,
			&bytes.Buffer{},
			time.Now().UTC(),
			bytes.NewReader(bytes.Repeat([]byte{0x64}, 64)),
		); err == nil {
			t.Fatalf("caller-selected command was accepted: %q", command)
		}
	}
}

func TestRunRejectsArgumentsBeyondOneFixedSubcommand(t *testing.T) {
	if err := run(context.Background(), nil, &bytes.Buffer{}); err == nil {
		t.Fatal("empty command was accepted")
	}
	if err := run(
		context.Background(),
		[]string{keyInitCommand, "/tmp/key"},
		&bytes.Buffer{},
	); err == nil {
		t.Fatal("caller-selected path argument was accepted")
	}
}

func TestStartLabReceivesCanceledSignalContext(t *testing.T) {
	root := t.TempDir()
	moduleRoot := filepath.Join(root, "network-sidecar")
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(moduleRoot, "go.mod"),
		[]byte("module github.com/kysion/kyclash/network-sidecar\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := runAtWithStart(
		ctx,
		startLabCommand,
		root,
		&bytes.Buffer{},
		time.Now().UTC(),
		bytes.NewReader(bytes.Repeat([]byte{0x65}, 128)),
		func(
			received context.Context,
			_ externalpeerhost.Layout,
			_ io.Reader,
		) error {
			calls++
			if !errors.Is(received.Err(), context.Canceled) {
				t.Fatal("start-lab did not receive canceled signal context")
			}
			return received.Err()
		},
	)
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled start dispatch err=%v calls=%d", err, calls)
	}
}

func TestLayerInputCommandsAreNoArgumentFixedDispatches(t *testing.T) {
	root := t.TempDir()
	moduleRoot := filepath.Join(root, "network-sidecar")
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(moduleRoot, "go.mod"),
		[]byte("module github.com/kysion/kyclash/network-sidecar\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	layerACalls := 0
	layerBCalls := 0
	approvalCalls := 0
	layerA := func(layout externalpeerhost.Layout) error {
		layerACalls++
		if layout.RepositoryRoot != root {
			t.Fatal("Layer A received a caller-selected root")
		}
		return nil
	}
	layerB := func(
		ctx context.Context,
		layout externalpeerhost.Layout,
	) (externalpeerhost.LayerBInputState, error) {
		layerBCalls++
		if ctx == nil || layout.RepositoryRoot != root {
			t.Fatal("Layer B did not receive the fixed context/layout")
		}
		return externalpeerhost.LayerBPinPublished, nil
	}
	approve := func(
		ctx context.Context,
		layout externalpeerhost.Layout,
	) error {
		approvalCalls++
		if ctx == nil || layout.RepositoryRoot != root {
			t.Fatal("baseline approval did not receive the fixed context/layout")
		}
		return nil
	}
	var layerAOutput bytes.Buffer
	if err := runAtWithInitializers(
		context.Background(),
		layerAInputsInitCommand,
		root,
		&layerAOutput,
		time.Now().UTC(),
		bytes.NewReader(bytes.Repeat([]byte{0x41}, 64)),
		layerA,
		layerB,
		nil,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if layerAOutput.String() != "layer_a_inputs_initialized=true\n" ||
		layerACalls != 1 || layerBCalls != 0 {
		t.Fatalf(
			"unexpected Layer A dispatch: output=%q a=%d b=%d",
			layerAOutput.String(),
			layerACalls,
			layerBCalls,
		)
	}
	var layerBOutput bytes.Buffer
	if err := runAtWithInitializers(
		context.Background(),
		layerBInputsInitCommand,
		root,
		&layerBOutput,
		time.Now().UTC(),
		bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)),
		layerA,
		layerB,
		nil,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if layerBOutput.String() !=
		"layer_b_inputs_state=layer-b-pin-inputs-published\n" ||
		layerACalls != 1 || layerBCalls != 1 {
		t.Fatalf(
			"unexpected Layer B dispatch: output=%q a=%d b=%d",
			layerBOutput.String(),
			layerACalls,
			layerBCalls,
		)
	}
	var approvalOutput bytes.Buffer
	if err := runAtWithInitializers(
		context.Background(),
		layerBBaselineApproveCommand,
		root,
		&approvalOutput,
		time.Now().UTC(),
		bytes.NewReader(bytes.Repeat([]byte{0x44}, 64)),
		layerA,
		layerB,
		approve,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if approvalOutput.String() !=
		"layer_b_listener_baselines_approved=true\n" ||
		approvalCalls != 1 {
		t.Fatalf(
			"unexpected approval dispatch: output=%q calls=%d",
			approvalOutput.String(),
			approvalCalls,
		)
	}
	for _, value := range []string{
		layerAInputsInitCommand + "=/tmp/input",
		layerBInputsInitCommand + "=/tmp/input",
		layerBBaselineApproveCommand + "=/tmp/input",
	} {
		if err := runAtWithInitializers(
			context.Background(),
			value,
			root,
			&bytes.Buffer{},
			time.Now().UTC(),
			bytes.NewReader(bytes.Repeat([]byte{0x43}, 64)),
			layerA,
			layerB,
			approve,
			nil,
		); err == nil {
			t.Fatalf("parameterized layer command was accepted: %q", value)
		}
	}
}
