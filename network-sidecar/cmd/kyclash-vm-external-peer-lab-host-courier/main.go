package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeerhost"
)

const (
	keyInitCommand               = "key-init"
	managementKeyInitCommand     = "management-key-init"
	managementHostKeyPinCommand  = "management-host-key-pin"
	layerAInputsInitCommand      = "layer-a-inputs-init"
	layerBInputsInitCommand      = "layer-b-inputs-init"
	layerBBaselineApproveCommand = "layer-b-listener-baseline-approve"
	startLabCommand              = "start-lab"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	if run(ctx, os.Args[1:], os.Stdout) != nil {
		_, _ = fmt.Fprintln(os.Stderr, "external-peer host courier refused")
		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	arguments []string,
	output io.Writer,
) error {
	if len(arguments) != 1 || output == nil {
		return externalpeerhost.ErrUnsafeHostCourier
	}
	repositoryRoot, err := os.Getwd()
	if err != nil {
		return externalpeerhost.ErrUnsafeHostCourier
	}
	return runAt(
		ctx,
		arguments[0],
		repositoryRoot,
		output,
		time.Now().UTC(),
		rand.Reader,
	)
}

func runAt(
	ctx context.Context,
	command string,
	repositoryRoot string,
	output io.Writer,
	now time.Time,
	entropy io.Reader,
) error {
	return runAtWithStart(
		ctx,
		command,
		repositoryRoot,
		output,
		now,
		entropy,
		startFixedLab,
	)
}

type fixedLabStarter func(context.Context, externalpeerhost.Layout, io.Reader) error

func runAtWithStart(
	ctx context.Context,
	command string,
	repositoryRoot string,
	output io.Writer,
	now time.Time,
	entropy io.Reader,
	start fixedLabStarter,
) error {
	return runAtWithInitializers(
		ctx,
		command,
		repositoryRoot,
		output,
		now,
		entropy,
		externalpeerhost.InitializeLayerAInputs,
		initializeFixedLayerB,
		approveFixedLayerBListenerBaselines,
		start,
	)
}

type layerAInitializer func(externalpeerhost.Layout) error
type layerBInitializer func(
	context.Context,
	externalpeerhost.Layout,
) (externalpeerhost.LayerBInputState, error)
type layerBBaselineApprover func(
	context.Context,
	externalpeerhost.Layout,
) error

func runAtWithInitializers(
	ctx context.Context,
	command string,
	repositoryRoot string,
	output io.Writer,
	now time.Time,
	entropy io.Reader,
	layerA layerAInitializer,
	layerB layerBInitializer,
	approveBaseline layerBBaselineApprover,
	start fixedLabStarter,
) error {
	if output == nil || entropy == nil {
		return externalpeerhost.ErrUnsafeHostCourier
	}
	layout, err := externalpeerhost.FixedLayout(repositoryRoot)
	if err != nil {
		return err
	}
	switch command {
	case keyInitCommand:
		if err := externalpeerhost.InitializeKeyStore(layout, entropy); err != nil {
			return err
		}
		_, err = io.WriteString(output, "courier_key_initialized=true\n")
		return err
	case managementKeyInitCommand:
		if err := externalpeerhost.InitializeManagementKeys(
			layout,
			entropy,
		); err != nil {
			return err
		}
		_, err = io.WriteString(output, "management_keys_initialized=true\n")
		return err
	case managementHostKeyPinCommand:
		if err := externalpeerhost.PinReviewedManagementHostKeys(
			layout,
		); err != nil {
			return err
		}
		_, err = io.WriteString(output, "management_host_keys_pinned=true\n")
		return err
	case layerAInputsInitCommand:
		if layerA == nil {
			return externalpeerhost.ErrUnsafeHostCourier
		}
		if err := layerA(layout); err != nil {
			return err
		}
		_, err = io.WriteString(output, "layer_a_inputs_initialized=true\n")
		return err
	case layerBInputsInitCommand:
		if ctx == nil || layerB == nil {
			return externalpeerhost.ErrUnsafeHostCourier
		}
		state, err := layerB(ctx, layout)
		if err != nil {
			return err
		}
		_, err = io.WriteString(
			output,
			"layer_b_inputs_state="+string(state)+"\n",
		)
		return err
	case layerBBaselineApproveCommand:
		if ctx == nil || approveBaseline == nil {
			return externalpeerhost.ErrUnsafeHostCourier
		}
		if err := approveBaseline(ctx, layout); err != nil {
			return err
		}
		_, err = io.WriteString(
			output,
			"layer_b_listener_baselines_approved=true\n",
		)
		return err
	case startLabCommand:
		if ctx == nil || start == nil {
			return externalpeerhost.ErrUnsafeHostCourier
		}
		if err := start(ctx, layout, entropy); err != nil {
			return err
		}
		_, err = io.WriteString(output, "external_peer_lab_started=true\n")
		return err
	default:
		return externalpeerhost.ErrUnsafeHostCourier
	}
}

func initializeFixedLayerB(
	ctx context.Context,
	layout externalpeerhost.Layout,
) (externalpeerhost.LayerBInputState, error) {
	executor, err := externalpeerhost.NewOSCommandExecutor(layout)
	if err != nil {
		return "", err
	}
	tart, err := externalpeerhost.NewFixedTartResolver(layout)
	if err != nil {
		return "", err
	}
	return externalpeerhost.InitializeLayerBInputs(
		ctx,
		layout,
		executor,
		externalpeerhost.NewSystemRunnerClock(),
		tart,
	)
}

func approveFixedLayerBListenerBaselines(
	ctx context.Context,
	layout externalpeerhost.Layout,
) error {
	executor, err := externalpeerhost.NewOSCommandExecutor(layout)
	if err != nil {
		return err
	}
	tart, err := externalpeerhost.NewFixedTartResolver(layout)
	if err != nil {
		return err
	}
	return externalpeerhost.ApproveLayerBListenerBaselines(
		ctx,
		layout,
		executor,
		externalpeerhost.NewSystemRunnerClock(),
		tart,
	)
}

func startFixedLab(
	ctx context.Context,
	layout externalpeerhost.Layout,
	entropy io.Reader,
) error {
	executor, err := externalpeerhost.NewOSCommandExecutor(layout)
	if err != nil {
		return err
	}
	tart, err := externalpeerhost.NewFixedTartResolver(layout)
	if err != nil {
		return err
	}
	runner, err := externalpeerhost.NewStartLabRunner(
		layout,
		executor,
		externalpeerhost.NewSystemRunnerClock(),
		tart,
		entropy,
	)
	if err != nil {
		return err
	}
	return runner.StartLab(ctx)
}
