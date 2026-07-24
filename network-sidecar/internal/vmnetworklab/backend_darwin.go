//go:build darwin && kyclash_utun && (kyclash_vm_network_lab || kyclash_vm_external_peer_lab)

package vmnetworklab

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/ipc"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/userspace"
)

var ErrRouteJournal = errors.New("VM network route journal operation failed")

type RouteCoordinator struct {
	mu        sync.Mutex
	store     JournalStore
	inspector RouteInspector
	executor  RouteExecutor
	record    JournalRecord
	bound     bool
	applied   bool
	deleted   bool
}

func NewRouteCoordinator(store JournalStore, inspector RouteInspector, executor RouteExecutor) *RouteCoordinator {
	return &RouteCoordinator{store: store, inspector: inspector, executor: executor, record: NewJournalRecord()}
}

func (coordinator *RouteCoordinator) Record() JournalRecord {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return coordinator.record
}

func (coordinator *RouteCoordinator) Preflight() error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	snapshot, err := coordinator.inspector.Snapshot()
	if err != nil {
		return err
	}
	return ValidatePreflight(snapshot)
}

func (coordinator *RouteCoordinator) SetMihomo(record JournalRecord) error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if err := record.Validate(); err != nil {
		return err
	}
	coordinator.record = record
	return coordinator.store.Save(record)
}

func (coordinator *RouteCoordinator) BindTunnel(instanceID, operationID, interfaceName string) error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if !validIdentifier(instanceID) || !validIdentifier(operationID) || !validUTUN(interfaceName) {
		return ErrRouteJournal
	}
	record := coordinator.record
	record.SidecarInstanceID = instanceID
	record.TunnelGeneration = "tun." + operationID
	record.TunnelInterface = interfaceName
	record.State = StateStartPending
	if err := record.Validate(); err != nil {
		return err
	}
	if err := coordinator.store.Save(record); err != nil {
		return err
	}
	coordinator.record = record
	coordinator.bound = true
	return nil
}

func (coordinator *RouteCoordinator) Apply() error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if !coordinator.bound || coordinator.applied || coordinator.deleted || coordinator.record.State == StateRecoveryOnly {
		if coordinator.applied {
			return nil
		}
		return ErrRouteJournal
	}
	record := coordinator.record
	record.State = StateAddPending
	if err := coordinator.store.Save(record); err != nil {
		return err
	}
	if err := coordinator.executor.Add(record.TunnelInterface); err != nil {
		return err
	}
	snapshot, err := coordinator.inspector.Snapshot()
	if err != nil {
		return errors.Join(ErrRouteAmbiguous, err)
	}
	if err := ValidateApplied(snapshot, record.TunnelInterface); err != nil {
		return errors.Join(ErrRouteAmbiguous, err)
	}
	record.State = StateApplied
	if err := coordinator.store.Save(record); err != nil {
		return errors.Join(ErrRouteAmbiguous, err)
	}
	coordinator.record = record
	coordinator.applied = true
	return nil
}

func (coordinator *RouteCoordinator) Delete() error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if !coordinator.bound || coordinator.deleted {
		return nil
	}
	record := coordinator.record
	if record.State != StateApplied && record.State != StateDeletePending && record.State != StateTeardown {
		return ErrRouteJournal
	}
	record.State = StateDeletePending
	if err := coordinator.store.Save(record); err != nil {
		return err
	}
	if err := coordinator.executor.Delete(record.TunnelInterface); err != nil {
		// A failed delete is not proof of presence or absence. Inspect below;
		// only a clean no-exact result is accepted.
		if snapshot, inspectErr := coordinator.inspector.Snapshot(); inspectErr != nil {
			return errors.Join(ErrRouteAmbiguous, err, inspectErr)
		} else if _, exists := hasExactRoute(snapshot.all(), PrivatePrefix()); exists {
			return errors.Join(ErrRouteAmbiguous, err)
		}
	}
	snapshot, err := coordinator.inspector.Snapshot()
	if err != nil {
		return errors.Join(ErrRouteAmbiguous, err)
	}
	if _, exists := hasExactRoute(snapshot.all(), PrivatePrefix()); exists {
		return ErrRouteAmbiguous
	}
	record.State = StateTeardown
	if err := coordinator.store.Save(record); err != nil {
		return errors.Join(ErrRouteAmbiguous, err)
	}
	coordinator.record = record
	coordinator.deleted = true
	coordinator.applied = false
	return nil
}

func (coordinator *RouteCoordinator) Finalize(absence func() error) error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if err := absence(); err != nil {
		return errors.Join(ErrRouteAmbiguous, err)
	}
	record := coordinator.record
	record.State = StateReleased
	if err := coordinator.store.Save(record); err != nil {
		return err
	}
	if err := coordinator.store.Remove(); err != nil {
		return err
	}
	coordinator.record = record
	return nil
}

func (coordinator *RouteCoordinator) MarkRecoveryOnly() error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	record := coordinator.record
	record.State = StateRecoveryOnly
	if err := coordinator.store.Save(record); err != nil {
		return err
	}
	coordinator.record = record
	return nil
}

type Backend struct {
	mu          sync.Mutex
	base        *userspace.Backend
	coordinator *RouteCoordinator
	coexistence *RuntimeCoexistenceVerifier
	instanceID  string
	interfaceID string
	prepared    bool
	active      bool
	closed      bool
}

// RuntimeCoexistenceVerifier is the only source of the App's Mihomo
// coexistence claim. Every private echo samples the exact child/controller,
// both lab interfaces and routes, and the read-only system snapshots before
// and after payload traffic.
type RuntimeCoexistenceVerifier struct {
	manager     *MihomoManager
	coordinator *RouteCoordinator
	inspector   RouteInspector
	baseline    SystemSnapshot
}

func NewRuntimeCoexistenceVerifier(
	manager *MihomoManager,
	coordinator *RouteCoordinator,
	inspector RouteInspector,
	baseline SystemSnapshot,
) (*RuntimeCoexistenceVerifier, error) {
	if manager == nil || coordinator == nil || inspector == nil {
		return nil, errors.New("missing VM network coexistence authority")
	}
	return &RuntimeCoexistenceVerifier{
		manager: manager, coordinator: coordinator, inspector: inspector, baseline: baseline,
	}, nil
}

func (verifier *RuntimeCoexistenceVerifier) Verify(ctx context.Context, tunnelInterface string) error {
	if verifier == nil || verifier.manager == nil || verifier.coordinator == nil || verifier.inspector == nil ||
		!validUTUN(tunnelInterface) || tunnelInterface == MihomoInterface {
		return errors.New("invalid VM network coexistence proof request")
	}
	record := verifier.coordinator.Record()
	if record.State != StateApplied || record.TunnelInterface != tunnelInterface ||
		record.MihomoChild != verifier.manager.Identity() {
		return errors.New("VM network ownership facts changed")
	}
	mihomo, err := verifier.manager.Snapshot(ctx)
	if err != nil || mihomo.PID != record.MihomoChild.PID || mihomo.Device != MihomoInterface ||
		!mihomo.Covering || !mihomo.Config.TUNEnabled || mihomo.Config.Device != MihomoInterface {
		return errors.New("Mihomo coexistence facts changed")
	}
	current, err := CaptureSystemSnapshot(verifier.inspector)
	if err != nil {
		return err
	}
	if !bytes.Equal(current.DNSHash[:], verifier.baseline.DNSHash[:]) ||
		!bytes.Equal(current.ProxyHash[:], verifier.baseline.ProxyHash[:]) ||
		!equalStrings(current.DefaultRoutes, verifier.baseline.DefaultRoutes) {
		return errors.New("DNS, default route, or system proxy snapshot changed")
	}
	return ValidateApplied(current.Routes, tunnelInterface)
}

func NewBackend(
	privateKey []byte,
	roots *x509.CertPool,
	instanceID string,
	coordinator *RouteCoordinator,
	coexistence *RuntimeCoexistenceVerifier,
) (*Backend, error) {
	if coordinator == nil || coexistence == nil || coexistence.coordinator != coordinator {
		return nil, errors.New("missing VM network route coordinator")
	}
	base, err := userspace.New(privateKey, roots, instanceID)
	if err != nil {
		return nil, err
	}
	return &Backend{
		base: base, coordinator: coordinator, coexistence: coexistence, instanceID: instanceID,
	}, nil
}

func (backend *Backend) Prepare(ctx context.Context, networkProfile *profile.Profile, operationID string) (ipc.TunnelDeviceFacts, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed || backend.prepared {
		return ipc.TunnelDeviceFacts{}, userspace.ErrInvalidState
	}
	facts, err := backend.base.Prepare(ctx, networkProfile, operationID)
	if err != nil {
		return ipc.TunnelDeviceFacts{}, err
	}
	if !validUTUN(facts.InterfaceName) || facts.InstanceID != backend.instanceID || facts.OperationID != operationID {
		_ = backend.base.Close()
		return ipc.TunnelDeviceFacts{}, errors.New("real utun ownership facts are invalid")
	}
	if err := backend.coordinator.BindTunnel(facts.InstanceID, facts.OperationID, facts.InterfaceName); err != nil {
		_ = backend.base.Close()
		return ipc.TunnelDeviceFacts{}, err
	}
	backend.interfaceID = facts.InterfaceName
	backend.prepared = true
	return facts, nil
}

func (backend *Backend) Connect(ctx context.Context, transport profile.Transport, endpoint profile.NormalizedEndpoint) error {
	backend.mu.Lock()
	if backend.closed || !backend.prepared || backend.active {
		backend.mu.Unlock()
		return userspace.ErrInvalidState
	}
	backend.mu.Unlock()
	if err := backend.base.Connect(ctx, transport, endpoint); err != nil {
		return err
	}
	backend.mu.Lock()
	backend.active = true
	backend.mu.Unlock()
	return nil
}

func (backend *Backend) Health(ctx context.Context) (ipc.Health, error) {
	backend.mu.Lock()
	if backend.closed || !backend.active {
		backend.mu.Unlock()
		return ipc.Health{}, userspace.ErrInvalidState
	}
	backend.mu.Unlock()
	health, err := backend.base.Health(ctx)
	if err != nil || !health.Reachable {
		return health, err
	}
	// The carrier is positively healthy before the fixed private route is
	// made durable or installed.  Apply is idempotent for subsequent carrier
	// samples and the route remains during break-before-make switching.
	if err := backend.coordinator.Apply(); err != nil {
		return ipc.Health{}, err
	}
	return health, nil
}

func (backend *Backend) PrivateReachability(ctx context.Context) (ipc.PrivateReachability, error) {
	backend.mu.Lock()
	if backend.closed || !backend.active || backend.interfaceID == "" {
		backend.mu.Unlock()
		return ipc.PrivateReachability{}, userspace.ErrInvalidState
	}
	interfaceID := backend.interfaceID
	backend.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := backend.coexistence.Verify(ctx, interfaceID); err != nil {
		return ipc.PrivateReachability{}, err
	}
	probeContext, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dialer := net.Dialer{
		Timeout:   2 * time.Second,
		LocalAddr: &net.TCPAddr{IP: netip.MustParseAddr("10.88.0.1").AsSlice()},
	}
	start := time.Now()
	connection, err := dialer.DialContext(probeContext, "tcp", PrivateEcho)
	if err != nil {
		return ipc.PrivateReachability{}, errors.New("fixed private echo unavailable")
	}
	defer connection.Close()
	stopDeadline := context.AfterFunc(probeContext, func() { _ = connection.SetDeadline(time.Now()) })
	defer stopDeadline()
	payload := []byte(EchoPayload)
	if _, err := connection.Write(payload); err != nil {
		return ipc.PrivateReachability{}, errors.New("fixed private echo write failed")
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil || string(response) != EchoPayload {
		return ipc.PrivateReachability{}, errors.New("fixed private echo response failed")
	}
	if err := backend.coexistence.Verify(probeContext, interfaceID); err != nil {
		return ipc.PrivateReachability{}, err
	}
	latency := time.Since(start).Milliseconds()
	if latency < 0 {
		latency = 0
	}
	if latency > int64(^uint32(0)) {
		latency = int64(^uint32(0))
	}
	coexisting := true
	return ipc.PrivateReachability{
		Reachable:        true,
		LatencyMS:        uint32(latency),
		MihomoCoexisting: &coexisting,
	}, nil
}

func (backend *Backend) Disconnect(ctx context.Context) error {
	backend.mu.Lock()
	if backend.closed || !backend.active {
		backend.mu.Unlock()
		return userspace.ErrInvalidState
	}
	backend.mu.Unlock()
	if err := backend.base.Disconnect(ctx); err != nil {
		return err
	}
	backend.mu.Lock()
	backend.active = false
	backend.mu.Unlock()
	return nil
}

func (backend *Backend) Stop(ctx context.Context) error {
	backend.mu.Lock()
	if backend.closed || !backend.prepared || backend.active {
		backend.mu.Unlock()
		return userspace.ErrInvalidState
	}
	backend.mu.Unlock()
	if err := backend.coordinator.Delete(); err != nil {
		return err
	}
	if err := backend.base.Stop(ctx); err != nil {
		return err
	}
	backend.mu.Lock()
	backend.prepared = false
	backend.interfaceID = ""
	backend.mu.Unlock()
	return nil
}

func (backend *Backend) Close() error {
	backend.mu.Lock()
	if backend.closed {
		backend.mu.Unlock()
		return nil
	}
	active := backend.active
	prepared := backend.prepared
	backend.mu.Unlock()
	var cleanupErr error
	if active {
		cleanupErr = errors.Join(cleanupErr, backend.base.Disconnect(context.Background()))
		backend.mu.Lock()
		backend.active = false
		backend.mu.Unlock()
	}
	if prepared {
		if err := backend.coordinator.Delete(); err != nil {
			// Preserve the utun while route state is ambiguous. Closing it would
			// break the locked route-before-tunnel cleanup interlock.
			return errors.Join(cleanupErr, err)
		}
		cleanupErr = errors.Join(cleanupErr, backend.base.Stop(context.Background()))
	}
	cleanupErr = errors.Join(cleanupErr, backend.base.Close())
	backend.mu.Lock()
	backend.closed = true
	backend.prepared = false
	backend.active = false
	backend.interfaceID = ""
	backend.mu.Unlock()
	return cleanupErr
}

var _ ipc.Backend = (*Backend)(nil)
var _ ipc.PrivateReachabilityBackend = (*Backend)(nil)
