// Package userspace binds the IPC data-plane contract to wireguard-go and
// explicit KyClash packet carriers. Default and lab builds use its unprivileged
// netstack; the reviewed macOS production build uses an owned utun device.
package userspace

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
	"github.com/kysion/kyclash/network-sidecar/internal/identifier"
	"github.com/kysion/kyclash/network-sidecar/internal/ipc"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/wgcarrier"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var ErrInvalidState = errors.New("invalid userspace data-plane state")

type Backend struct {
	mu              sync.Mutex
	privateKey      []byte
	roots           *x509.CertPool
	wireGuard       *device.Device
	network         *netstack.Net
	switchboard     *wgcarrier.Switchboard
	active          profile.Transport
	closed          bool
	dialer          func(context.Context, profile.Transport, profile.NormalizedEndpoint) (carrier.Carrier, error)
	operationCancel atomic.Pointer[operationCancellation]
	probeAddress    netip.AddrPort
	instanceID      string
	interfaceName   string
	ownerOperation  string
}

type operationCancellation struct {
	cancel context.CancelFunc
}

func New(privateKey []byte, labRoots *x509.CertPool, instanceID string) (*Backend, error) {
	if len(privateKey) != 32 || !validOwnerID(instanceID) {
		return nil, ErrInvalidState
	}
	backend := &Backend{privateKey: append([]byte(nil), privateKey...), roots: labRoots, instanceID: instanceID}
	backend.dialer = backend.dialCarrier
	return backend, nil
}

// NewLab enables a bounded payload probe over the userspace WireGuard
// netstack. It is used only by the networking-dev lab executable.
func NewLab(privateKey []byte, labRoots *x509.CertPool, probeAddress netip.AddrPort, instanceID string) (*Backend, error) {
	backend, err := New(privateKey, labRoots, instanceID)
	if err != nil || !probeAddress.IsValid() {
		return nil, ErrInvalidState
	}
	backend.probeAddress = probeAddress
	return backend, nil
}

func (backend *Backend) Prepare(_ context.Context, networkProfile *profile.Profile, operationID string) (ipc.TunnelDeviceFacts, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed || backend.wireGuard != nil || networkProfile == nil || len(backend.privateKey) != 32 || !validOwnerID(operationID) {
		return ipc.TunnelDeviceFacts{}, ErrInvalidState
	}
	prefixes := make([]netip.Prefix, 0, len(networkProfile.Tunnel.LocalAddresses))
	for _, value := range networkProfile.Tunnel.LocalAddresses {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.IsValid() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return ipc.TunnelDeviceFacts{}, ErrInvalidState
		}
		prefixes = append(prefixes, prefix)
	}
	tunnel, network, interfaceName, err := createTunnel(prefixes, profile.TunnelMTU)
	if err != nil {
		return ipc.TunnelDeviceFacts{}, fmt.Errorf("create WireGuard tunnel: %w", err)
	}
	board := wgcarrier.NewSwitchboard()
	bind, err := wgcarrier.NewBind(board, "kyclash-peer")
	if err != nil {
		_ = tunnel.Close()
		return ipc.TunnelDeviceFacts{}, err
	}
	wireGuard := device.NewDevice(tunnel, bind, device.NewLogger(device.LogLevelSilent, ""))
	// netstack reports its TUN as immediately up. Quiesce the empty device
	// before installing a peer so no handshake timer starts without a carrier.
	if err := wireGuard.Down(); err != nil {
		wireGuard.Close()
		_ = board.Shutdown()
		return ipc.TunnelDeviceFacts{}, fmt.Errorf("quiesce empty userspace WireGuard: %w", err)
	}
	if err := configure(wireGuard, backend.privateKey, networkProfile); err != nil {
		wireGuard.Close()
		_ = board.Shutdown()
		return ipc.TunnelDeviceFacts{}, err
	}
	// netstack TUN starts wireguard-go during configuration. Keep the prepared
	// device down until Rust explicitly selects and attaches one carrier.
	if err := wireGuard.Down(); err != nil {
		wireGuard.Close()
		_ = board.Shutdown()
		return ipc.TunnelDeviceFacts{}, fmt.Errorf("quiesce prepared userspace WireGuard: %w", err)
	}
	clear(backend.privateKey)
	backend.privateKey = nil
	backend.switchboard = board
	backend.wireGuard = wireGuard
	backend.network = network
	backend.interfaceName = interfaceName
	backend.ownerOperation = operationID
	hasIPv4, hasIPv6 := addressFamilies(networkProfile)
	return ipc.TunnelDeviceFacts{InterfaceName: backend.interfaceName, MTU: profile.TunnelMTU, HasIPv4: hasIPv4, HasIPv6: hasIPv6, InstanceID: backend.instanceID, OperationID: operationID}, nil
}

func (backend *Backend) Connect(ctx context.Context, transport profile.Transport, endpoint profile.NormalizedEndpoint) error {
	backend.mu.Lock()
	if backend.closed || backend.wireGuard == nil || backend.switchboard == nil || backend.active != "" || backend.operationCancel.Load() != nil {
		backend.mu.Unlock()
		return ErrInvalidState
	}
	dialContext, cancel := context.WithCancel(ctx)
	operation := &operationCancellation{cancel: cancel}
	if !backend.operationCancel.CompareAndSwap(nil, operation) {
		cancel()
		backend.mu.Unlock()
		return ErrInvalidState
	}
	backend.mu.Unlock()

	packetCarrier, err := backend.dialer(dialContext, transport, endpoint)
	cancel()
	backend.operationCancel.CompareAndSwap(operation, nil)
	backend.mu.Lock()
	if err != nil {
		backend.mu.Unlock()
		return err
	}
	defer backend.mu.Unlock()
	if backend.closed || backend.wireGuard == nil || backend.switchboard == nil || backend.active != "" {
		_ = packetCarrier.Close()
		return ErrInvalidState
	}
	if err := backend.switchboard.Attach(packetCarrier); err != nil {
		_ = packetCarrier.Close()
		return err
	}
	if err := backend.wireGuard.Up(); err != nil {
		_ = backend.switchboard.Close()
		return fmt.Errorf("start WireGuard device: %w", err)
	}
	backend.active = transport
	return nil
}

func (backend *Backend) Health(ctx context.Context) (ipc.Health, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	backend.mu.Lock()
	if backend.closed || backend.active == "" || backend.wireGuard == nil || backend.switchboard == nil || backend.operationCancel.Load() != nil {
		backend.mu.Unlock()
		return ipc.Health{}, ErrInvalidState
	}
	operationContext, cancel := context.WithTimeout(ctx, healthOperationTimeout)
	operation := &operationCancellation{cancel: cancel}
	if !backend.operationCancel.CompareAndSwap(nil, operation) {
		cancel()
		backend.mu.Unlock()
		return ipc.Health{}, ErrInvalidState
	}
	network, probe, board := backend.network, backend.probeAddress, backend.switchboard
	backend.mu.Unlock()
	defer func() {
		cancel()
		backend.operationCancel.CompareAndSwap(operation, nil)
	}()
	if probe.IsValid() {
		var connection net.Conn
		var err error
		for {
			var candidate net.Conn
			candidate, err = network.DialContextTCPAddrPort(operationContext, probe)
			if err == nil {
				connection = candidate
				break
			}
			select {
			case <-time.After(10 * time.Millisecond):
			case <-operationContext.Done():
				return ipc.Health{}, operationContext.Err()
			}
		}
		defer connection.Close()
		stopDeadline := context.AfterFunc(operationContext, func() {
			_ = connection.SetDeadline(time.Now())
		})
		defer stopDeadline()
		payload := []byte("kyclash-health-v1")
		if _, err = connection.Write(payload); err != nil {
			if operationContext.Err() != nil {
				return ipc.Health{}, operationContext.Err()
			}
			return ipc.Health{}, err
		}
		response := make([]byte, len(payload))
		if _, err = io.ReadFull(connection, response); err != nil || string(response) != string(payload) {
			if operationContext.Err() != nil {
				return ipc.Health{}, operationContext.Err()
			}
			return ipc.Health{}, ErrInvalidState
		}
	}
	return sampleCarrierHealth(operationContext, board)
}

const (
	healthOperationTimeout = 12 * time.Second
	healthProbeCount       = 4
)

func sampleCarrierHealth(ctx context.Context, board *wgcarrier.Switchboard) (ipc.Health, error) {
	if board == nil {
		return ipc.Health{}, ErrInvalidState
	}
	samples := make([]time.Duration, 0, healthProbeCount)
	lost := 0
	for index := 0; index < healthProbeCount; index++ {
		probeContext, cancel := context.WithTimeout(ctx, healthProbeTimeout)
		latency, err := board.Probe(probeContext)
		cancel()
		if err == nil {
			samples = append(samples, latency)
			continue
		}
		if ctx.Err() != nil {
			return ipc.Health{}, ctx.Err()
		}
		if errors.Is(err, carrier.ErrProbeUnavailable) {
			return ipc.Health{}, err
		}
		// KYNP v1 ping/pong intentionally has no correlation payload. Stop at
		// the first missing response and count the remaining bounded sample as
		// lost so a delayed pong can never be treated as a new measurement.
		lost += healthProbeCount - index
		break
	}
	latency, jitter := summarizeLatency(samples)
	return ipc.Health{
		Reachable:   lost == 0,
		LatencyMS:   latency,
		JitterMS:    jitter,
		LossPercent: uint8(lost * 100 / healthProbeCount),
	}, nil
}

func summarizeLatency(samples []time.Duration) (uint32, uint32) {
	if len(samples) == 0 {
		return 0, 0
	}
	var total, deltaTotal time.Duration
	for index, sample := range samples {
		if sample < 0 {
			sample = 0
		}
		total += sample
		if index != 0 {
			delta := sample - samples[index-1]
			if delta < 0 {
				delta = -delta
			}
			deltaTotal += delta
		}
	}
	latency := total / time.Duration(len(samples))
	var jitter time.Duration
	if len(samples) > 1 {
		jitter = deltaTotal / time.Duration(len(samples)-1)
	}
	return boundedMilliseconds(latency), boundedMilliseconds(jitter)
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

func (backend *Backend) Disconnect(context.Context) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed || backend.wireGuard == nil || backend.switchboard == nil || backend.active == "" || backend.operationCancel.Load() != nil {
		return ErrInvalidState
	}
	if err := backend.wireGuard.Down(); err != nil {
		return fmt.Errorf("stop WireGuard device: %w", err)
	}
	// wireguard-go closes the Bind while going down, which detaches and closes
	// the active switchboard carrier.
	backend.active = ""
	return nil
}

func (backend *Backend) Stop(context.Context) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed || backend.wireGuard == nil || backend.active != "" || backend.operationCancel.Load() != nil {
		return ErrInvalidState
	}
	backend.wireGuard.Close()
	if backend.switchboard != nil {
		_ = backend.switchboard.Shutdown()
	}
	backend.wireGuard = nil
	backend.network = nil
	backend.switchboard = nil
	backend.interfaceName = ""
	backend.ownerOperation = ""
	return nil
}

func (backend *Backend) Close() error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed {
		return nil
	}
	backend.closed = true
	if operation := backend.operationCancel.Swap(nil); operation != nil {
		operation.cancel()
	}
	if backend.wireGuard != nil {
		backend.wireGuard.Close()
	}
	if backend.switchboard != nil {
		_ = backend.switchboard.Shutdown()
	}
	clear(backend.privateKey)
	backend.privateKey = nil
	backend.wireGuard = nil
	backend.network = nil
	backend.switchboard = nil
	backend.active = ""
	backend.interfaceName = ""
	backend.ownerOperation = ""
	return nil
}

// DialLabTCP is the intentionally narrow payload-test boundary. It is only
// enabled for NewLab instances and returns one connection, never the raw
// netstack pointer used by production lifecycle code.
func (backend *Backend) DialLabTCP(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
	backend.mu.Lock()
	if backend.closed || backend.network == nil || !backend.probeAddress.IsValid() {
		backend.mu.Unlock()
		return nil, ErrInvalidState
	}
	network := backend.network
	backend.mu.Unlock()
	return network.DialContextTCPAddrPort(ctx, address)
}

func validOwnerID(value string) bool {
	return identifier.Valid(value)
}

func addressFamilies(networkProfile *profile.Profile) (bool, bool) {
	var hasIPv4, hasIPv6 bool
	for _, value := range networkProfile.Tunnel.LocalAddresses {
		prefix, _ := netip.ParsePrefix(value)
		hasIPv4 = hasIPv4 || prefix.Addr().Is4()
		hasIPv6 = hasIPv6 || prefix.Addr().Is6()
	}
	return hasIPv4, hasIPv6
}

func (backend *Backend) dialCarrier(ctx context.Context, transport profile.Transport, endpoint profile.NormalizedEndpoint) (carrier.Carrier, error) {
	timeout := 10 * time.Second
	switch transport {
	case profile.QUIC:
		return carrier.DialQUIC(ctx, carrier.QUICConfig{Address: endpoint.Address, ServerName: endpoint.ServerName, RootCAs: backend.roots, Timeout: timeout})
	case profile.WSS:
		return carrier.DialWSS(ctx, carrier.WSSConfig{URL: endpoint.URL, RootCAs: backend.roots, Timeout: timeout})
	case profile.TCP:
		return carrier.DialTCP(ctx, carrier.TCPConfig{Address: endpoint.Address, ServerName: endpoint.ServerName, RootCAs: backend.roots, Timeout: timeout})
	default:
		return nil, ErrInvalidState
	}
}

func configure(wireGuard *device.Device, privateKey []byte, networkProfile *profile.Profile) error {
	peerKey, err := networkProfile.PeerKeyBytes()
	if err != nil {
		return err
	}
	defer clear(peerKey)
	var configuration strings.Builder
	fmt.Fprintf(&configuration, "private_key=%s\nreplace_peers=true\npublic_key=%s\nprotocol_version=1\nreplace_allowed_ips=true\n", hex.EncodeToString(privateKey), hex.EncodeToString(peerKey))
	for _, prefix := range networkProfile.Site.PrivateCIDRs {
		fmt.Fprintf(&configuration, "allowed_ip=%s\n", prefix)
	}
	fmt.Fprintf(&configuration, "endpoint=kyclash-peer\npersistent_keepalive_interval=%d\n", networkProfile.Tunnel.KeepaliveSeconds)
	err = wireGuard.IpcSet(configuration.String())
	configuration.Reset()
	if err != nil {
		return fmt.Errorf("configure userspace WireGuard: %w", err)
	}
	return nil
}

var _ ipc.Backend = (*Backend)(nil)
