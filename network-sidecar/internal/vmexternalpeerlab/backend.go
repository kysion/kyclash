package vmexternalpeerlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/ipc"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/userspace"
)

var ErrInvalidBackendState = errors.New("invalid external-peer backend state")

// SupervisorClient is the complete privileged authority visible to the
// external-peer harness. It exposes no caller-selected route, path, command,
// endpoint, or process operation.
type SupervisorClient interface {
	PrepareFixture(context.Context) error
	BindTunnel(context.Context, string, string, string) error
	ApplyRoute(context.Context) error
	VerifyRuntime(context.Context) error
	DeleteRoute(context.Context) error
	ReleaseRuntime(context.Context) error
}

// SSHVerification contains only the two fixed, run-bound SSH proof results.
// It deliberately cannot carry an address, command, key, or credential.
type SSHVerification struct {
	InProcessVerified bool
	SystemVerified    bool
}

// SSHVerifier proves the fixed in-process no-shell nonce service and the
// fixed Apple OpenSSH forced-command service for the current run.
type SSHVerifier interface {
	VerifySSH(context.Context, string, bool) (SSHVerification, error)
}

type packetBackend interface {
	Prepare(context.Context, *profile.Profile, string) (ipc.TunnelDeviceFacts, error)
	Connect(context.Context, profile.Transport, profile.NormalizedEndpoint) error
	Health(context.Context) (ipc.Health, error)
	Disconnect(context.Context) error
	Stop(context.Context) error
	Close() error
}

type echoVerifier interface {
	VerifyEcho(context.Context) (time.Duration, error)
}

type Backend struct {
	operation sync.Mutex

	base          packetBackend
	supervisor    SupervisorClient
	echo          echoVerifier
	ssh           SSHVerifier
	instanceID    string
	interfaceID   string
	strictProfile []byte
	endpoints     map[profile.Transport]profile.NormalizedEndpoint

	fixturePrepared bool
	prepared        bool
	everPrepared    bool
	active          bool
	activeTransport profile.Transport
	routeOwned      bool
	routeApplied    bool
	baseClosed      bool
	released        bool
	closed          bool
}

func newBackend(
	base packetBackend,
	strictProfile *profile.Profile,
	instanceID string,
	supervisor SupervisorClient,
	echo echoVerifier,
	ssh SSHVerifier,
) (*Backend, error) {
	encoded, endpoints, err := freezeStrictProfile(strictProfile)
	if err != nil || base == nil || supervisor == nil || echo == nil || ssh == nil || !validToken(instanceID) {
		return nil, ErrInvalidBackendState
	}
	return &Backend{
		base:          base,
		supervisor:    supervisor,
		echo:          echo,
		ssh:           ssh,
		instanceID:    instanceID,
		strictProfile: encoded,
		endpoints:     endpoints,
	}, nil
}

func (backend *Backend) Prepare(
	ctx context.Context,
	networkProfile *profile.Profile,
	operationID string,
) (ipc.TunnelDeviceFacts, error) {
	backend.operation.Lock()
	defer backend.operation.Unlock()
	if backend.closed || backend.everPrepared || !validToken(operationID) ||
		!backend.matchesStrictProfile(networkProfile) {
		return ipc.TunnelDeviceFacts{}, ErrInvalidBackendState
	}
	if err := backend.supervisor.PrepareFixture(ctx); err != nil {
		return ipc.TunnelDeviceFacts{}, err
	}
	backend.fixturePrepared = true
	facts, err := backend.base.Prepare(ctx, networkProfile, operationID)
	if err != nil {
		return ipc.TunnelDeviceFacts{}, backend.abortPrepare(err)
	}
	backend.everPrepared = true
	if !validUTUN(facts.InterfaceName) ||
		facts.InstanceID != backend.instanceID ||
		facts.OperationID != operationID ||
		facts.MTU != profile.TunnelMTU ||
		!facts.HasIPv4 ||
		facts.HasIPv6 {
		return ipc.TunnelDeviceFacts{}, backend.abortPrepare(ErrInvalidBackendState)
	}
	if err := backend.supervisor.BindTunnel(
		ctx,
		facts.InstanceID,
		facts.OperationID,
		facts.InterfaceName,
	); err != nil {
		return ipc.TunnelDeviceFacts{}, backend.abortPrepare(err)
	}
	backend.interfaceID = facts.InterfaceName
	backend.prepared = true
	return facts, nil
}

func (backend *Backend) Connect(
	ctx context.Context,
	transport profile.Transport,
	endpoint profile.NormalizedEndpoint,
) error {
	backend.operation.Lock()
	defer backend.operation.Unlock()
	expected, exists := backend.endpoints[transport]
	if backend.closed || !backend.prepared || backend.active || !exists || endpoint != expected {
		return ErrInvalidBackendState
	}
	if err := backend.base.Connect(ctx, transport, endpoint); err != nil {
		return err
	}
	backend.active = true
	backend.activeTransport = transport
	return nil
}

func (backend *Backend) Health(ctx context.Context) (ipc.Health, error) {
	backend.operation.Lock()
	defer backend.operation.Unlock()
	if backend.closed || !backend.prepared || !backend.active {
		return ipc.Health{}, ErrInvalidBackendState
	}
	health, err := backend.base.Health(ctx)
	if err != nil {
		// A carrier that was previously healthy enough to install the exact
		// route may become black-holed by the peer's fixed impairment. The base
		// health probe reports that bounded loss as a context deadline. Normalize
		// only this steady-state case into a typed unhealthy sample; startup
		// timeouts and every other error remain failures and can never be used as
		// fallback evidence.
		if backend.routeApplied && errors.Is(err, context.DeadlineExceeded) {
			return ipc.Health{Reachable: false, LossPercent: 100}, nil
		}
		return health, err
	}
	if !health.Reachable || backend.routeApplied {
		return health, err
	}
	// The add transaction may have reached the kernel before an error was
	// returned. From this point onward cleanup must attempt the typed delete
	// and prove absence before the real utun can be released.
	backend.routeOwned = true
	if err := backend.supervisor.ApplyRoute(ctx); err != nil {
		return ipc.Health{}, err
	}
	backend.routeApplied = true
	return health, nil
}

func (backend *Backend) PrivateReachability(ctx context.Context) (ipc.PrivateReachability, error) {
	backend.operation.Lock()
	defer backend.operation.Unlock()
	if backend.closed || !backend.prepared || !backend.active || !backend.routeApplied {
		return ipc.PrivateReachability{}, ErrInvalidBackendState
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := backend.supervisor.VerifyRuntime(ctx); err != nil {
		return ipc.PrivateReachability{}, err
	}
	latency, err := backend.echo.VerifyEcho(ctx)
	if err != nil {
		return ipc.PrivateReachability{}, err
	}
	requireSystemSSH := backend.activeTransport == profile.TCP
	sshResult, err := backend.ssh.VerifySSH(ctx, backend.interfaceID, requireSystemSSH)
	if err != nil || !sshResult.InProcessVerified || requireSystemSSH && !sshResult.SystemVerified {
		if err != nil {
			return ipc.PrivateReachability{}, err
		}
		return ipc.PrivateReachability{}, errors.New("fixed SSH proof failed")
	}
	// The second observation binds both SSH proofs and the echo result to the
	// same still-owned route/Mihomo transaction.
	if err := backend.supervisor.VerifyRuntime(ctx); err != nil {
		return ipc.PrivateReachability{}, err
	}
	latencyMS := boundedMilliseconds(latency)
	verified := true
	systemVerified := requireSystemSSH && sshResult.SystemVerified
	return ipc.PrivateReachability{
		Reachable:          true,
		LatencyMS:          latencyMS,
		MihomoCoexisting:   &verified,
		OverlaySSHVerified: &verified,
		SystemSSHVerified:  &systemVerified,
	}, nil
}

func (backend *Backend) Disconnect(ctx context.Context) error {
	backend.operation.Lock()
	defer backend.operation.Unlock()
	if backend.closed || !backend.prepared || !backend.active {
		return ErrInvalidBackendState
	}
	if err := backend.base.Disconnect(ctx); err != nil {
		return err
	}
	// The exact route intentionally remains owned and installed while the
	// caller performs break-before-make carrier fallback.
	backend.active = false
	backend.activeTransport = ""
	return nil
}

func (backend *Backend) Stop(ctx context.Context) error {
	backend.operation.Lock()
	defer backend.operation.Unlock()
	if backend.closed || !backend.prepared || backend.active {
		return ErrInvalidBackendState
	}
	if err := backend.deleteRoute(ctx); err != nil {
		return err
	}
	if err := backend.base.Stop(ctx); err != nil {
		return err
	}
	backend.prepared = false
	return nil
}

func (backend *Backend) Close() error {
	backend.operation.Lock()
	defer backend.operation.Unlock()
	if backend.closed {
		return nil
	}
	var cleanupErr error
	if backend.active {
		cleanupErr = errors.Join(cleanupErr, backend.base.Disconnect(context.Background()))
		backend.active = false
	}
	if err := backend.deleteRoute(context.Background()); err != nil {
		// Preserve the backend and real utun while route deletion is
		// ambiguous. A later Close may retry the same typed transaction.
		return errors.Join(cleanupErr, err)
	}
	if !backend.baseClosed {
		if err := backend.base.Close(); err != nil {
			return errors.Join(cleanupErr, err)
		}
		backend.baseClosed = true
		backend.prepared = false
	}
	if backend.fixturePrepared && !backend.released {
		if err := backend.supervisor.ReleaseRuntime(context.Background()); err != nil {
			return errors.Join(cleanupErr, err)
		}
		backend.released = true
	}
	backend.closed = true
	return cleanupErr
}

func (backend *Backend) abortPrepare(cause error) error {
	if cleanupErr := backend.base.Close(); cleanupErr != nil {
		// Do not release the supervisor-owned fixture while the real-utun
		// backend may still be alive. Close can retry this exact interlock.
		return errors.Join(cause, cleanupErr)
	}
	backend.baseClosed = true
	var cleanupErr error
	if backend.fixturePrepared {
		releaseErr := backend.supervisor.ReleaseRuntime(context.Background())
		cleanupErr = releaseErr
		if releaseErr == nil {
			backend.released = true
		}
	}
	if cleanupErr == nil {
		backend.closed = true
	}
	return errors.Join(cause, cleanupErr)
}

func (backend *Backend) deleteRoute(ctx context.Context) error {
	if !backend.routeOwned {
		return nil
	}
	if err := backend.supervisor.DeleteRoute(ctx); err != nil {
		return err
	}
	backend.routeOwned = false
	backend.routeApplied = false
	return nil
}

func (backend *Backend) matchesStrictProfile(candidate *profile.Profile) bool {
	encoded, _, err := freezeStrictProfile(candidate)
	return err == nil && bytes.Equal(encoded, backend.strictProfile)
}

func freezeStrictProfile(
	value *profile.Profile,
) ([]byte, map[profile.Transport]profile.NormalizedEndpoint, error) {
	if value == nil || value.Validate() != nil ||
		value.ProfileID != ProfileID ||
		value.Site.ID != SiteID ||
		len(value.Site.PrivateCIDRs) != 1 ||
		value.Site.PrivateCIDRs[0] != PrivateCIDR ||
		len(value.Tunnel.LocalAddresses) != 1 ||
		value.Tunnel.LocalAddresses[0] != ClientCIDR ||
		value.Transports.Primary != profile.QUIC ||
		len(value.Transports.Fallbacks) != 2 ||
		value.Transports.Fallbacks[0] != profile.WSS ||
		value.Transports.Fallbacks[1] != profile.TCP ||
		len(value.Transports.Endpoints) != 3 {
		return nil, nil, ErrInvalidBackendState
	}
	expectedOrder := [...]profile.Transport{profile.QUIC, profile.WSS, profile.TCP}
	endpoints := make(map[profile.Transport]profile.NormalizedEndpoint, len(expectedOrder))
	var peerAddress netip.Addr
	ports := make(map[uint16]struct{}, len(expectedOrder))
	for index, transport := range expectedOrder {
		if value.Transports.Endpoints[index].Transport != transport {
			return nil, nil, ErrInvalidBackendState
		}
		endpoint, err := value.Endpoint(transport)
		if err != nil {
			return nil, nil, ErrInvalidBackendState
		}
		address, err := netip.ParseAddr(endpoint.ServerName)
		if err != nil || !address.Is4() || !address.IsPrivate() || address.IsLoopback() ||
			address.IsUnspecified() || privatePrefix.Contains(address) || coverPrefix.Contains(address) {
			return nil, nil, ErrInvalidBackendState
		}
		if peerAddress.IsValid() && address != peerAddress {
			return nil, nil, ErrInvalidBackendState
		}
		peerAddress = address
		_, portText, err := net.SplitHostPort(endpoint.Address)
		portValue, portErr := strconv.ParseUint(portText, 10, 16)
		port := uint16(portValue)
		if err != nil || portErr != nil || port < 20_000 || port > 60_000 {
			return nil, nil, ErrInvalidBackendState
		}
		if _, duplicate := ports[port]; duplicate {
			return nil, nil, ErrInvalidBackendState
		}
		ports[port] = struct{}{}
		if transport == profile.WSS {
			parsed, parseErr := url.Parse(endpoint.URL)
			if parseErr != nil || parsed.Path != "/kynp" {
				return nil, nil, ErrInvalidBackendState
			}
		}
		endpoints[transport] = endpoint
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, nil, ErrInvalidBackendState
	}
	return encoded, endpoints, nil
}

type fixedEchoVerifier struct{}

func (fixedEchoVerifier) VerifyEcho(ctx context.Context) (time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	probeContext, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dialer := net.Dialer{
		Timeout:   2 * time.Second,
		LocalAddr: &net.TCPAddr{IP: netip.MustParseAddr("10.88.0.1").AsSlice()},
	}
	started := time.Now()
	connection, err := dialer.DialContext(probeContext, "tcp", PrivateEcho)
	if err != nil {
		return 0, errors.New("fixed private echo unavailable")
	}
	defer connection.Close()
	stopDeadline := context.AfterFunc(probeContext, func() {
		_ = connection.SetDeadline(time.Now())
	})
	defer stopDeadline()
	payload := []byte(EchoPayload)
	if _, err := connection.Write(payload); err != nil {
		return 0, errors.New("fixed private echo write failed")
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil ||
		!bytes.Equal(response, payload) {
		return 0, errors.New("fixed private echo response failed")
	}
	return time.Since(started), nil
}

func boundedMilliseconds(value time.Duration) uint32 {
	milliseconds := value.Milliseconds()
	if milliseconds <= 0 {
		return 0
	}
	if milliseconds > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(milliseconds)
}

var _ ipc.Backend = (*Backend)(nil)
var _ ipc.PrivateReachabilityBackend = (*Backend)(nil)
var _ packetBackend = (*userspace.Backend)(nil)
