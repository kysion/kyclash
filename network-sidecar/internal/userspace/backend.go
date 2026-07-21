// Package userspace binds the IPC data-plane contract to wireguard-go's
// unprivileged netstack and explicit KyClash packet carriers.
package userspace

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
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
	switchboard     *wgcarrier.Switchboard
	active          profile.Transport
	connectDelay    time.Duration
	closed          bool
	dialer          func(context.Context, profile.Transport, profile.NormalizedEndpoint) (carrier.Carrier, error)
	operationCancel context.CancelFunc
}

func New(privateKey []byte, labRoots *x509.CertPool) (*Backend, error) {
	if len(privateKey) != 32 {
		return nil, ErrInvalidState
	}
	backend := &Backend{privateKey: append([]byte(nil), privateKey...), roots: labRoots}
	backend.dialer = backend.dialCarrier
	return backend, nil
}

func (backend *Backend) Prepare(_ context.Context, networkProfile *profile.Profile) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed || backend.wireGuard != nil || networkProfile == nil || len(backend.privateKey) != 32 {
		return ErrInvalidState
	}
	addresses := make([]netip.Addr, 0, len(networkProfile.Tunnel.LocalAddresses))
	for _, value := range networkProfile.Tunnel.LocalAddresses {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ErrInvalidState
		}
		addresses = append(addresses, prefix.Addr())
	}
	tunnel, _, err := netstack.CreateNetTUN(addresses, nil, profile.TunnelMTU)
	if err != nil {
		return fmt.Errorf("create userspace tunnel: %w", err)
	}
	board := wgcarrier.NewSwitchboard()
	bind, err := wgcarrier.NewBind(board, "kyclash-peer")
	if err != nil {
		_ = tunnel.Close()
		return err
	}
	wireGuard := device.NewDevice(tunnel, bind, device.NewLogger(device.LogLevelSilent, ""))
	if err := configure(wireGuard, backend.privateKey, networkProfile); err != nil {
		wireGuard.Close()
		_ = board.Shutdown()
		return err
	}
	clear(backend.privateKey)
	backend.privateKey = nil
	backend.switchboard = board
	backend.wireGuard = wireGuard
	return nil
}

func (backend *Backend) Connect(ctx context.Context, transport profile.Transport, endpoint profile.NormalizedEndpoint) error {
	started := time.Now()
	backend.mu.Lock()
	if backend.closed || backend.wireGuard == nil || backend.switchboard == nil || backend.active != "" || backend.operationCancel != nil {
		backend.mu.Unlock()
		return ErrInvalidState
	}
	dialContext, cancel := context.WithCancel(ctx)
	backend.operationCancel = cancel
	backend.mu.Unlock()

	packetCarrier, err := backend.dialer(dialContext, transport, endpoint)
	cancel()
	backend.mu.Lock()
	backend.operationCancel = nil
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
		return fmt.Errorf("start userspace WireGuard: %w", err)
	}
	backend.active = transport
	backend.connectDelay = time.Since(started)
	return nil
}

func (backend *Backend) Health(context.Context) (ipc.Health, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed || backend.active == "" || backend.wireGuard == nil {
		return ipc.Health{}, ErrInvalidState
	}
	latency := backend.connectDelay.Milliseconds()
	if latency < 0 {
		latency = 0
	}
	if latency > int64(^uint32(0)) {
		latency = int64(^uint32(0))
	}
	return ipc.Health{Reachable: true, LatencyMS: uint32(latency)}, nil
}

func (backend *Backend) Disconnect(context.Context) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed || backend.wireGuard == nil || backend.switchboard == nil || backend.active == "" {
		return ErrInvalidState
	}
	if err := backend.wireGuard.Down(); err != nil {
		return fmt.Errorf("stop userspace WireGuard: %w", err)
	}
	// wireguard-go closes the Bind while going down, which detaches and closes
	// the active switchboard carrier.
	backend.active = ""
	return nil
}

func (backend *Backend) Stop(context.Context) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed || backend.wireGuard == nil || backend.active != "" {
		return ErrInvalidState
	}
	backend.wireGuard.Close()
	if backend.switchboard != nil {
		_ = backend.switchboard.Shutdown()
	}
	backend.wireGuard = nil
	backend.switchboard = nil
	return nil
}

func (backend *Backend) Cancel(string) error {
	backend.mu.Lock()
	cancel := backend.operationCancel
	backend.mu.Unlock()
	if cancel == nil {
		return ErrInvalidState
	}
	cancel()
	return nil
}

func (backend *Backend) Close() error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed {
		return nil
	}
	backend.closed = true
	if backend.operationCancel != nil {
		backend.operationCancel()
		backend.operationCancel = nil
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
	backend.switchboard = nil
	backend.active = ""
	return nil
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
