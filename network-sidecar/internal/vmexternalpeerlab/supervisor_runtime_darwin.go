//go:build darwin && kyclash_utun && kyclash_vm_external_peer_lab

package vmexternalpeerlab

import (
	"context"
	"errors"
	"sync"

	"github.com/kysion/kyclash/network-sidecar/internal/vmnetworklab"
)

// SupervisorRuntime owns the complete privileged client-side transaction.
// The App and harness can reach it only through SupervisorRequestHandler's
// closed operation set; all filesystem, process, route, and Mihomo identity
// is compiled into this composition.
type SupervisorRuntime struct {
	mu sync.Mutex

	store       vmnetworklab.JournalStore
	inspector   vmnetworklab.RouteInspector
	executor    vmnetworklab.RouteExecutor
	contract    vmnetworklab.MihomoContract
	baseline    vmnetworklab.SystemSnapshot
	routes      *vmnetworklab.RouteCoordinator
	mihomo      *vmnetworklab.MihomoManager
	coexistence *vmnetworklab.RuntimeCoexistenceVerifier

	fixturePrepared bool
	tunnelBound     bool
	routeApplied    bool
	released        bool
}

func ExternalMihomoContract() vmnetworklab.MihomoContract {
	return vmnetworklab.MihomoContract{
		StageRoot: StageRoot, StateRoot: StateRoot, SocketPath: MihomoSocket,
		StateRootMode: 0o711, Executable: MihomoPath, ConfigPath: MihomoConfig, ConfigSHA256: MihomoConfigSHA256,
	}
}

// NewSupervisorRuntime performs recovery and clean-state validation before
// the App socket may be opened. An ambiguous retained journal is never
// discarded and prevents a new transaction.
func NewSupervisorRuntime(ctx context.Context) (*SupervisorRuntime, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	inspector := vmnetworklab.DarwinRouteInspector{}
	executor := vmnetworklab.DarwinRouteExecutor{}
	store := vmnetworklab.NewJournalStore(JournalPath, true)
	contract := ExternalMihomoContract()
	baseline, err := vmnetworklab.CaptureSystemSnapshot(inspector)
	if err != nil {
		return nil, err
	}
	if retained, exists, loadErr := store.Load(); loadErr != nil {
		return nil, loadErr
	} else if exists {
		if err := vmnetworklab.RecoverJournalWithMihomoContract(
			ctx, store, retained, inspector, executor, baseline, contract,
		); err != nil {
			return nil, err
		}
		baseline, err = vmnetworklab.CaptureSystemSnapshot(inspector)
		if err != nil {
			return nil, err
		}
	}
	if err := vmnetworklab.ValidateForeignAbsenceWithMihomoContract(baseline.Routes, contract); err != nil {
		return nil, err
	}
	routes := vmnetworklab.NewRouteCoordinator(store, inspector, executor)
	return &SupervisorRuntime{
		store: store, inspector: inspector, executor: executor, contract: contract,
		baseline: baseline, routes: routes, mihomo: vmnetworklab.NewMihomoManagerWithContract(inspector, contract),
	}, nil
}

func (runtime *SupervisorRuntime) HandleSupervisorRequest(ctx context.Context, request SupervisorRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.released {
		return errors.New("external-peer runtime is already released")
	}
	switch request.Operation {
	case PrepareFixture:
		return runtime.prepareFixture(ctx)
	case BindTunnel:
		if !runtime.fixturePrepared || runtime.tunnelBound {
			return errors.New("external-peer tunnel bind is out of order")
		}
		if err := runtime.routes.BindTunnel(request.InstanceID, request.OperationID, request.TunnelInterface); err != nil {
			return err
		}
		runtime.tunnelBound = true
		return nil
	case ApplyRoute:
		if !runtime.fixturePrepared || !runtime.tunnelBound || runtime.routeApplied {
			return errors.New("external-peer route apply is out of order")
		}
		if err := runtime.routes.Apply(); err != nil {
			return err
		}
		runtime.routeApplied = true
		return nil
	case VerifyRuntime:
		if !runtime.routeApplied || runtime.coexistence == nil {
			return errors.New("external-peer runtime is not applied")
		}
		return runtime.coexistence.Verify(ctx, runtime.routes.Record().TunnelInterface)
	case DeleteRoute:
		if !runtime.tunnelBound || !runtime.routeApplied {
			return errors.New("external-peer route delete is out of order")
		}
		if err := runtime.routes.Delete(); err != nil {
			return err
		}
		runtime.routeApplied = false
		return nil
	case ReleaseRuntime:
		if !runtime.fixturePrepared || runtime.routeApplied {
			return errors.New("external-peer release is out of order")
		}
		return runtime.release(ctx)
	default:
		return errors.New("unsupported external-peer supervisor operation")
	}
}

func (runtime *SupervisorRuntime) prepareFixture(ctx context.Context) error {
	if runtime.fixturePrepared || runtime.tunnelBound || runtime.routeApplied {
		return errors.New("external-peer fixture prepare is out of order")
	}
	record := runtime.routes.Record()
	if err := runtime.routes.SetMihomo(record); err != nil {
		return err
	}
	if err := runtime.mihomo.Start(ctx); err != nil {
		return err
	}
	record = runtime.routes.Record()
	record.MihomoChild = runtime.mihomo.Identity()
	if err := runtime.routes.SetMihomo(record); err != nil {
		return err
	}
	if err := runtime.routes.Preflight(); err != nil {
		return err
	}
	coexistence, err := vmnetworklab.NewRuntimeCoexistenceVerifier(
		runtime.mihomo, runtime.routes, runtime.inspector, runtime.baseline,
	)
	if err != nil {
		return err
	}
	runtime.coexistence = coexistence
	runtime.fixturePrepared = true
	return nil
}

func (runtime *SupervisorRuntime) release(ctx context.Context) error {
	if err := runtime.mihomo.Stop(ctx); err != nil {
		_ = runtime.routes.MarkRecoveryOnly()
		return err
	}
	finalRecord := runtime.routes.Record()
	if err := runtime.routes.Finalize(func() error {
		return vmnetworklab.VerifyFinalAbsenceWithMihomoContract(
			runtime.inspector, runtime.baseline, finalRecord.TunnelInterface, runtime.contract,
		)
	}); err != nil {
		_ = runtime.routes.MarkRecoveryOnly()
		return err
	}
	runtime.fixturePrepared = false
	runtime.released = true
	return nil
}

// Close converges App EOF, TERM, cancellation, and command failure through
// the same route-first cleanup. If an exact route cannot be proved absent,
// the journal is retained and the real utun owner must remain alive.
func (runtime *SupervisorRuntime) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.released {
		return nil
	}
	var result error
	if runtime.routeApplied {
		if err := runtime.routes.Delete(); err != nil {
			_ = runtime.routes.MarkRecoveryOnly()
			return err
		}
		runtime.routeApplied = false
	}
	if runtime.fixturePrepared {
		result = errors.Join(result, runtime.release(ctx))
		return result
	}
	// A journal may have been created before Mihomo became ready. Positive
	// absence is still required before removing that start-intent record.
	finalRecord := runtime.routes.Record()
	if _, exists, err := runtime.store.Load(); err != nil {
		return err
	} else if exists {
		if err := runtime.routes.Finalize(func() error {
			return vmnetworklab.VerifyFinalAbsenceWithMihomoContract(
				runtime.inspector, runtime.baseline, finalRecord.TunnelInterface, runtime.contract,
			)
		}); err != nil {
			_ = runtime.routes.MarkRecoveryOnly()
			return err
		}
	}
	runtime.released = true
	return result
}

var _ SupervisorRequestHandler = (*SupervisorRuntime)(nil)
