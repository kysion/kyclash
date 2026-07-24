package externalpeer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/wgcarrier"
	quicgo "github.com/quic-go/quic-go"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	ErrInvalidPeerConfig = errors.New("invalid external-peer runtime configuration")
	ErrCarrierOverlap    = errors.New("external-peer carrier already active")
	ErrWrongClientSource = errors.New("external-peer client source mismatch")
	ErrPeerChildClosed   = errors.New("external-peer child closed")
)

const carrierEndpointID = "kyclash-vm-external-peer-lab"

type PeerConfig struct {
	RunID           string
	Now             time.Time
	ExpiresAt       time.Time
	Client          ClientExpectation
	ClientArtifacts ClientPublicArtifacts

	PeerPlatformUUID       string
	PeerIPv4               netip.Addr
	PeerMAC                string
	SystemSSHHostPublicKey []byte
}

type PeerStatus struct {
	ActiveTransport profile.Transport
	QUICBlocked     bool
	WSSRefused      bool
	DroppedQUIC     uint64
	QUICEchoProofs  uint64
	QUICSSHProofs   uint64
	WSSEchoProofs   uint64
	WSSSSHProofs    uint64
}

type Peer struct {
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	done      chan struct{}
	wait      sync.WaitGroup

	config     PeerConfig
	client     ClientPublicDescriptor
	identity   *PeerIdentity
	artifactMu sync.RWMutex
	descriptor PeerPublicDescriptor
	artifacts  PeerPublicArtifacts

	board     *wgcarrier.Switchboard
	wireGuard *device.Device
	network   *netstack.Net

	listeners              []*externalCarrierListener
	echo                   net.Listener
	overlaySSHListener     net.Listener
	systemSSHProxyListener net.Listener
	overlaySSH             *OverlaySSHServer

	mu              sync.Mutex
	active          *managedCarrier
	activeTransport profile.Transport
	carrierEpoch    uint64
	deviceUp        bool

	quicBlocked atomic.Bool
	wssRefused  atomic.Bool
	quicPackets *controlledPacketConn
	proofs      map[profile.Transport]*transportProof
}

type transportProof struct {
	echo uint64
	ssh  uint64
}

type transportProofToken struct {
	transport profile.Transport
	epoch     uint64
}

type externalCarrierListener struct {
	transport profile.Transport
	endpoint  profile.Endpoint
	accept    func(context.Context) (*managedCarrier, error)
	close     func() error
}

type reservedSockets struct {
	quic  net.PacketConn
	wss   net.Listener
	tcp   net.Listener
	ports [3]uint16
}

type managedCarrier struct {
	carrier.Carrier
	transport profile.Transport
	closeOnce sync.Once
	closed    chan struct{}
}

func (value *managedCarrier) Send(ctx context.Context, packet []byte) error {
	err := value.Carrier.Send(ctx, packet)
	if err != nil {
		value.signalClosed()
	}
	return err
}

func (value *managedCarrier) Receive(ctx context.Context) ([]byte, error) {
	packet, err := value.Carrier.Receive(ctx)
	if err != nil {
		value.signalClosed()
	}
	return packet, err
}

func (value *managedCarrier) Close() error {
	var closeErr error
	value.closeOnce.Do(func() {
		closeErr = value.Carrier.Close()
		close(value.closed)
	})
	return closeErr
}

func (value *managedCarrier) signalClosed() {
	value.closeOnce.Do(func() {
		_ = value.Carrier.Close()
		close(value.closed)
	})
}

func StartPeer(parent context.Context, config PeerConfig) (*Peer, error) {
	if parent == nil {
		parent = context.Background()
	}
	now := config.Now
	if now.IsZero() {
		now = time.Now().UTC()
		config.Now = now
	}
	if config.RunID == "" {
		config.RunID = config.Client.RunID
	}
	if config.ExpiresAt.IsZero() {
		config.ExpiresAt = time.Unix(config.ClientArtifactsExpiry(), 0)
	}
	if err := validatePeerConfig(config); err != nil {
		return nil, err
	}
	client, err := DecodeClientPublicDescriptor(
		config.ClientArtifacts.Descriptor,
		config.ClientArtifacts,
		config.Client,
	)
	if err != nil {
		return nil, err
	}
	if config.ExpiresAt.Unix() != client.ExpiresAt {
		return nil, ErrInvalidPeerConfig
	}
	if err := ValidateBindAddress(BindInterface, config.PeerIPv4); err != nil {
		return nil, err
	}
	identity, err := NewPeerIdentity(
		now,
		config.ExpiresAt,
		config.RunID,
		config.PeerIPv4,
		config.ClientArtifacts.TLSClientCSRDER,
	)
	if err != nil {
		return nil, err
	}
	cleanupIdentity := true
	defer func() {
		if cleanupIdentity {
			identity.Clear()
		}
	}()

	sockets, err := reserveCarrierSockets(config.PeerIPv4)
	if err != nil {
		return nil, err
	}
	closeReserved := true
	defer func() {
		if closeReserved {
			sockets.close()
		}
	}()

	tunnel, network, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(InnerPeerIPv4)},
		nil,
		profile.TunnelMTU,
	)
	if err != nil {
		return nil, fmt.Errorf("create external-peer netstack: %w", err)
	}
	board := wgcarrier.NewSwitchboard()
	bind, err := wgcarrier.NewBind(board, carrierEndpointID)
	if err != nil {
		_ = tunnel.Close()
		return nil, err
	}
	wireGuard := device.NewDevice(tunnel, bind, device.NewLogger(device.LogLevelSilent, ""))
	if err := wireGuard.Down(); err != nil {
		wireGuard.Close()
		return nil, err
	}
	if err := configureExternalPeer(
		wireGuard,
		identity.WireGuardPrivateKey,
		config.Client.WireGuardPublicKey,
	); err != nil {
		wireGuard.Close()
		return nil, err
	}
	if err := wireGuard.Down(); err != nil {
		wireGuard.Close()
		return nil, err
	}
	clear(identity.WireGuardPrivateKey)

	ctx, cancel := context.WithCancel(parent)
	peer := &Peer{
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		config:    config,
		client:    client,
		identity:  identity,
		board:     board,
		wireGuard: wireGuard,
		network:   network,
		proofs: map[profile.Transport]*transportProof{
			profile.QUIC: {},
			profile.WSS:  {},
			profile.TCP:  {},
		},
	}
	runtimeReady := false
	defer func() {
		if !runtimeReady {
			peer.shutdown()
			peer.wait.Wait()
			peer.clearSensitive()
		}
	}()

	if err := peer.openPrivateServices(); err != nil {
		return nil, err
	}
	listeners, packetControl, err := peer.openCarrierListeners(sockets)
	if err != nil {
		return nil, err
	}
	peer.listeners = listeners
	peer.quicPackets = packetControl
	closeReserved = false

	endpoints := make([]profile.Endpoint, 0, len(listeners))
	for _, listener := range listeners {
		endpoints = append(endpoints, listener.endpoint)
	}
	value, artifacts, err := identity.PublicArtifacts(PeerDescriptorConfig{
		RunID:                    config.RunID,
		IssuedAt:                 now.Truncate(time.Second),
		ExpiresAt:                config.ExpiresAt.Truncate(time.Second),
		ClientPlatformUUID:       config.Client.ClientPlatformUUID,
		PeerPlatformUUID:         config.PeerPlatformUUID,
		ClientIPv4:               config.Client.ClientIPv4,
		PeerIPv4:                 config.PeerIPv4,
		ClientMAC:                config.Client.ClientMAC,
		PeerMAC:                  config.PeerMAC,
		ClientWireGuardPublicKey: config.Client.WireGuardPublicKey,
		ClientOverlayPublicKey:   config.ClientArtifacts.OverlayClientPublicKey,
		Endpoints:                endpoints,
		SystemSSHHostPublicKey:   config.SystemSSHHostPublicKey,
	}, client)
	if err != nil {
		return nil, err
	}
	if err := attachPeerTransferManifest(config.RunID, &artifacts); err != nil {
		return nil, err
	}
	peer.descriptor = value
	peer.artifacts = artifacts

	for _, listener := range peer.listeners {
		peer.wait.Add(1)
		go peer.acceptLoop(listener)
	}
	peer.wait.Add(1)
	go peer.echoLoop()
	peer.wait.Add(1)
	go func() {
		defer peer.wait.Done()
		_ = peer.overlaySSH.Serve(peer.ctx)
	}()
	peer.wait.Add(1)
	go func() {
		defer peer.wait.Done()
		_ = ServeFixedSystemSSHProxy(peer.ctx, peer.systemSSHProxyListener)
	}()
	go func() {
		<-peer.ctx.Done()
		peer.shutdown()
		peer.wait.Wait()
		peer.clearSensitive()
		close(peer.done)
	}()
	runtimeReady = true
	cleanupIdentity = false
	return peer, nil
}

func (config PeerConfig) ClientArtifactsExpiry() int64 {
	var value ClientPublicDescriptor
	if strictDecode(config.ClientArtifacts.Descriptor, &value) != nil {
		return 0
	}
	return value.ExpiresAt
}

func (peer *Peer) Descriptor() PeerPublicDescriptor {
	peer.artifactMu.RLock()
	defer peer.artifactMu.RUnlock()
	value := peer.descriptor
	value.Endpoints = append([]profile.Endpoint(nil), value.Endpoints...)
	value.TransportOrder = append([]profile.Transport(nil), value.TransportOrder...)
	return value
}

func (peer *Peer) PublicArtifacts() PeerPublicArtifacts {
	peer.artifactMu.RLock()
	defer peer.artifactMu.RUnlock()
	return clonePeerArtifacts(peer.artifacts)
}

func (peer *Peer) runNonce() []byte {
	peer.artifactMu.RLock()
	defer peer.artifactMu.RUnlock()
	if peer.identity == nil {
		return nil
	}
	return append([]byte(nil), peer.identity.RunNonce...)
}

func (peer *Peer) Status() PeerStatus {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	var dropped uint64
	if peer.quicPackets != nil {
		dropped = peer.quicPackets.dropped.Load()
	}
	return PeerStatus{
		ActiveTransport: peer.activeTransport,
		QUICBlocked:     peer.quicBlocked.Load(),
		WSSRefused:      peer.wssRefused.Load(),
		DroppedQUIC:     dropped,
		QUICEchoProofs:  peer.proofs[profile.QUIC].echo,
		QUICSSHProofs:   peer.proofs[profile.QUIC].ssh,
		WSSEchoProofs:   peer.proofs[profile.WSS].echo,
		WSSSSHProofs:    peer.proofs[profile.WSS].ssh,
	}
}

func (peer *Peer) BlockQUICUDP() {
	peer.quicBlocked.Store(true)
	if peer.quicPackets != nil {
		peer.quicPackets.blocked.Store(true)
	}
}

func (peer *Peer) RefuseWSS() {
	peer.wssRefused.Store(true)
	peer.closeActive(profile.WSS)
}

func (peer *Peer) Close() error {
	if peer == nil {
		return nil
	}
	peer.closeOnce.Do(peer.cancel)
	<-peer.done
	return nil
}

func (peer *Peer) Done() <-chan struct{} { return peer.done }

func (peer *Peer) closeActive(transport profile.Transport) {
	peer.mu.Lock()
	active := peer.active
	if active == nil || peer.activeTransport != transport {
		peer.mu.Unlock()
		return
	}
	peer.active = nil
	peer.activeTransport = ""
	peer.carrierEpoch++
	if peer.deviceUp {
		_ = peer.wireGuard.Down()
		peer.deviceUp = false
	}
	_ = peer.board.Detach()
	peer.mu.Unlock()
	_ = active.Close()
}

func (peer *Peer) shutdown() {
	peer.closeOnce.Do(peer.cancel)
	peer.mu.Lock()
	active := peer.active
	peer.active = nil
	peer.activeTransport = ""
	peer.carrierEpoch++
	peer.deviceUp = false
	peer.mu.Unlock()
	if active != nil {
		_ = active.Close()
	}
	if peer.board != nil {
		_ = peer.board.Shutdown()
	}
	if peer.wireGuard != nil {
		peer.wireGuard.Close()
	}
	for _, listener := range peer.listeners {
		if listener != nil && listener.close != nil {
			_ = listener.close()
		}
	}
	if peer.echo != nil {
		_ = peer.echo.Close()
	}
	if peer.overlaySSH != nil {
		_ = peer.overlaySSH.Close()
	} else if peer.overlaySSHListener != nil {
		_ = peer.overlaySSHListener.Close()
	}
	if peer.systemSSHProxyListener != nil {
		_ = peer.systemSSHProxyListener.Close()
	}
}

func (peer *Peer) clearSensitive() {
	peer.artifactMu.Lock()
	defer peer.artifactMu.Unlock()
	if peer.identity != nil {
		peer.identity.Clear()
	}
	clearPeerArtifacts(&peer.artifacts)
}

func (peer *Peer) acceptLoop(listener *externalCarrierListener) {
	defer peer.wait.Done()
	for {
		candidate, err := listener.accept(peer.ctx)
		if err != nil {
			if peer.ctx.Err() != nil {
				return
			}
			continue
		}
		if err := peer.attach(candidate); err != nil {
			_ = candidate.Close()
		}
	}
}

func (peer *Peer) attach(candidate *managedCarrier) error {
	if candidate == nil {
		return ErrInvalidPeerConfig
	}
	peer.mu.Lock()
	if peer.ctx.Err() != nil || peer.active != nil {
		peer.mu.Unlock()
		return ErrCarrierOverlap
	}
	if err := peer.board.Attach(candidate); err != nil {
		peer.mu.Unlock()
		return err
	}
	if err := peer.wireGuard.Up(); err != nil {
		_ = peer.board.Detach()
		peer.mu.Unlock()
		return err
	}
	peer.active = candidate
	peer.activeTransport = candidate.transport
	peer.carrierEpoch++
	peer.deviceUp = true
	peer.mu.Unlock()
	peer.wait.Add(1)
	go func() {
		defer peer.wait.Done()
		select {
		case <-candidate.closed:
			peer.detach(candidate)
		case <-peer.ctx.Done():
		}
	}()
	return nil
}

func (peer *Peer) detach(candidate *managedCarrier) {
	peer.mu.Lock()
	if peer.active != candidate {
		peer.mu.Unlock()
		return
	}
	peer.active = nil
	peer.activeTransport = ""
	peer.carrierEpoch++
	if peer.deviceUp {
		_ = peer.wireGuard.Down()
		peer.deviceUp = false
	}
	_ = peer.board.Detach()
	peer.mu.Unlock()
}

func (peer *Peer) openPrivateServices() error {
	echo, err := peer.network.ListenTCPAddrPort(
		netip.AddrPortFrom(netip.MustParseAddr(InnerPeerIPv4), PrivateEchoPort),
	)
	if err != nil {
		return err
	}
	overlaySSHListener, err := peer.network.ListenTCPAddrPort(
		netip.AddrPortFrom(netip.MustParseAddr(InnerPeerIPv4), OverlaySSHPort),
	)
	if err != nil {
		_ = echo.Close()
		return err
	}
	systemSSHProxyListener, err := peer.network.ListenTCPAddrPort(
		netip.AddrPortFrom(netip.MustParseAddr(InnerPeerIPv4), SystemSSHPort),
	)
	if err != nil {
		_ = echo.Close()
		_ = overlaySSHListener.Close()
		return err
	}
	if err := verifyLocalSystemSSH(peer.ctx); err != nil {
		_ = echo.Close()
		_ = overlaySSHListener.Close()
		_ = systemSSHProxyListener.Close()
		return err
	}
	overlaySSH, err := NewOverlaySSHServer(
		overlaySSHListener,
		peer.identity.OverlayPrivateKey,
		peer.config.ClientArtifacts.OverlayClientPublicKey,
		peer.identity.RunNonce,
	)
	if err != nil {
		_ = echo.Close()
		_ = overlaySSHListener.Close()
		_ = systemSSHProxyListener.Close()
		return err
	}
	peer.echo = echo
	peer.overlaySSHListener = overlaySSHListener
	peer.systemSSHProxyListener = systemSSHProxyListener
	peer.overlaySSH = overlaySSH
	peer.overlaySSH.SetProofCallbackFactory(func() func() {
		token, ok := peer.captureTransportProofToken()
		if !ok {
			return nil
		}
		return func() {
			peer.recordTransportProof(token, false)
		}
	})
	return nil
}

func (peer *Peer) echoLoop() {
	defer peer.wait.Done()
	for {
		connection, err := peer.echo.Accept()
		if err != nil {
			return
		}
		peer.wait.Add(1)
		go func() {
			defer peer.wait.Done()
			defer connection.Close()
			token, validToken := peer.captureTransportProofToken()
			copied, _ := io.Copy(connection, connection)
			if copied > 0 && validToken {
				peer.recordTransportProof(token, true)
			}
		}()
	}
}

func (peer *Peer) captureTransportProofToken() (
	transportProofToken,
	bool,
) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.active == nil {
		return transportProofToken{}, false
	}
	return transportProofToken{
		transport: peer.activeTransport,
		epoch:     peer.carrierEpoch,
	}, true
}

func (peer *Peer) recordTransportProof(
	token transportProofToken,
	echo bool,
) {
	peer.mu.Lock()
	proof := peer.proofs[token.transport]
	if proof == nil ||
		peer.active == nil ||
		peer.activeTransport != token.transport ||
		peer.carrierEpoch != token.epoch {
		peer.mu.Unlock()
		return
	}
	if echo {
		proof.echo++
	} else {
		proof.ssh++
	}
	complete := proof.echo > 0 && proof.ssh > 0
	peer.mu.Unlock()
	if !complete {
		return
	}
	switch token.transport {
	case profile.QUIC:
		// Keep the existing QUIC carrier and UDP socket alive. The controlled
		// PacketConn drops subsequent datagrams so the client observes a
		// bounded health failure and performs the explicit Disconnect.
		peer.BlockQUICUDP()
	case profile.WSS:
		// The locked second impairment is an explicit WSS refusal/close after
		// the same-carrier echo and pinned overlay-SSH proof.
		peer.RefuseWSS()
	}
}

func (peer *Peer) openCarrierListeners(
	sockets reservedSockets,
) ([]*externalCarrierListener, *controlledPacketConn, error) {
	tlsConfig, err := makePeerTLSConfig(
		peer.identity,
		peer.config.ClientArtifacts,
		peer.config.RunID,
	)
	if err != nil {
		return nil, nil, err
	}
	packetControl := &controlledPacketConn{PacketConn: sockets.quic}
	quicTLS := tlsConfig.Clone()
	quicTLS.NextProtos = []string{QUICALPN}
	quicListener, err := quicgo.Listen(
		packetControl,
		quicTLS,
		&quicgo.Config{EnableDatagrams: true, HandshakeIdleTimeout: 5 * time.Second},
	)
	if err != nil {
		return nil, nil, err
	}
	listeners := []*externalCarrierListener{{
		transport: profile.QUIC,
		endpoint: profile.Endpoint{
			Transport: profile.QUIC,
			URL:       "https://" + net.JoinHostPort(peer.config.PeerIPv4.String(), strconv.Itoa(int(sockets.ports[0]))),
		},
		accept: func(ctx context.Context) (*managedCarrier, error) {
			connection, err := quicListener.Accept(ctx)
			if err != nil {
				return nil, err
			}
			if err := peer.validateAcceptedSource(connection.RemoteAddr()); err != nil {
				_ = connection.CloseWithError(1, "source refused")
				return nil, err
			}
			value, err := carrier.AcceptQUIC(connection)
			if err != nil {
				return nil, err
			}
			return newManagedCarrier(profile.QUIC, value), nil
		},
		close: quicListener.Close,
	}}

	wssTLSListener := tls.NewListener(sockets.wss, tlsConfig)
	wssAccepted := make(chan *managedCarrier, 4)
	wssErrors := make(chan error, 4)
	mux := http.NewServeMux()
	mux.HandleFunc(WSSPath, func(response http.ResponseWriter, request *http.Request) {
		if peer.wssRefused.Load() ||
			request.URL.Path != WSSPath ||
			request.URL.RawQuery != "" ||
			request.TLS == nil ||
			peer.validateAcceptedSourceString(request.RemoteAddr) != nil {
			http.Error(response, "refused", http.StatusForbidden)
			return
		}
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			select {
			case wssErrors <- err:
			default:
			}
			return
		}
		stream := carrier.NewStream(websocket.NetConn(
			context.Background(),
			connection,
			websocket.MessageBinary,
		))
		value := newManagedCarrier(profile.WSS, stream)
		select {
		case wssAccepted <- value:
			select {
			case <-value.closed:
			case <-peer.ctx.Done():
				_ = value.Close()
			}
		case <-peer.ctx.Done():
			_ = value.Close()
		}
	})
	wssServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	wssDone := make(chan struct{})
	go func() {
		defer close(wssDone)
		_ = wssServer.Serve(wssTLSListener)
	}()
	var closeWSS sync.Once
	listeners = append(listeners, &externalCarrierListener{
		transport: profile.WSS,
		endpoint: profile.Endpoint{
			Transport: profile.WSS,
			URL:       "wss://" + net.JoinHostPort(peer.config.PeerIPv4.String(), strconv.Itoa(int(sockets.ports[1]))) + WSSPath,
		},
		accept: func(ctx context.Context) (*managedCarrier, error) {
			select {
			case value := <-wssAccepted:
				return value, nil
			case err := <-wssErrors:
				return nil, err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		close: func() error {
			var closeErr error
			closeWSS.Do(func() {
				closeErr = wssServer.Close()
				if err := wssTLSListener.Close(); closeErr == nil && !errors.Is(err, net.ErrClosed) {
					closeErr = err
				}
				<-wssDone
			})
			return closeErr
		},
	})

	listeners = append(listeners, &externalCarrierListener{
		transport: profile.TCP,
		endpoint: profile.Endpoint{
			Transport: profile.TCP,
			URL:       "tcp://" + net.JoinHostPort(peer.config.PeerIPv4.String(), strconv.Itoa(int(sockets.ports[2]))),
		},
		accept: func(ctx context.Context) (*managedCarrier, error) {
			raw, err := acceptContext(ctx, sockets.tcp)
			if err != nil {
				return nil, err
			}
			if err := peer.validateAcceptedSource(raw.RemoteAddr()); err != nil {
				_ = raw.Close()
				return nil, err
			}
			connection := tls.Server(raw, tlsConfig)
			handshakeContext, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := connection.HandshakeContext(handshakeContext); err != nil {
				_ = connection.Close()
				return nil, err
			}
			return newManagedCarrier(profile.TCP, carrier.NewStream(connection)), nil
		},
		close: sockets.tcp.Close,
	})
	return listeners, packetControl, nil
}

func (peer *Peer) validateAcceptedSource(address net.Addr) error {
	if err := ValidateBindAddress(BindInterface, peer.config.PeerIPv4); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return ErrWrongClientSource
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil || parsed.Unmap() != peer.config.Client.ClientIPv4 {
		return ErrWrongClientSource
	}
	return nil
}

func (peer *Peer) validateAcceptedSourceString(address string) error {
	return peer.validateAcceptedSource(stringAddress(address))
}

type stringAddress string

func (value stringAddress) Network() string { return "tcp" }
func (value stringAddress) String() string  { return string(value) }

func ValidateBindAddress(interfaceName string, expected netip.Addr) error {
	if interfaceName != BindInterface ||
		!validPrivateAddr(expected) ||
		innerPrefix().Contains(expected) {
		return ErrInvalidPeerConfig
	}
	networkInterface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return ErrInvalidPeerConfig
	}
	addresses, err := networkInterface.Addrs()
	if err != nil {
		return ErrInvalidPeerConfig
	}
	matches := 0
	for _, value := range addresses {
		prefix, err := netip.ParsePrefix(value.String())
		if err == nil && prefix.Addr().Unmap() == expected {
			matches++
		}
	}
	if matches != 1 {
		return ErrInvalidPeerConfig
	}
	return nil
}

func validatePeerConfig(config PeerConfig) error {
	if !validRunID(config.RunID) ||
		config.RunID != config.Client.RunID ||
		config.Client.Now.IsZero() && config.Now.IsZero() ||
		!validUnderlayPair(config.Client.ClientIPv4, config.PeerIPv4) ||
		!validMAC(config.Client.ClientMAC) ||
		!validMAC(config.PeerMAC) ||
		equalMAC(config.Client.ClientMAC, config.PeerMAC) ||
		!validUUID(config.PeerPlatformUUID) ||
		config.PeerPlatformUUID == config.Client.ClientPlatformUUID ||
		len(config.Client.WireGuardPublicKey) != 32 ||
		len(config.SystemSSHHostPublicKey) == 0 {
		return ErrInvalidPeerConfig
	}
	return nil
}

func reserveCarrierSockets(peerIPv4 netip.Addr) (reservedSockets, error) {
	if !validPrivateAddr(peerIPv4) || innerPrefix().Contains(peerIPv4) {
		return reservedSockets{}, ErrInvalidPeerConfig
	}
	for attempt := 0; attempt < 64; attempt++ {
		ports, err := randomCarrierPorts()
		if err != nil {
			return reservedSockets{}, err
		}
		host := peerIPv4.String()
		quic, err := net.ListenPacket("udp4", net.JoinHostPort(host, strconv.Itoa(int(ports[0]))))
		if err != nil {
			continue
		}
		wss, err := net.Listen("tcp4", net.JoinHostPort(host, strconv.Itoa(int(ports[1]))))
		if err != nil {
			_ = quic.Close()
			continue
		}
		tcp, err := net.Listen("tcp4", net.JoinHostPort(host, strconv.Itoa(int(ports[2]))))
		if err != nil {
			_ = quic.Close()
			_ = wss.Close()
			continue
		}
		return reservedSockets{quic: quic, wss: wss, tcp: tcp, ports: ports}, nil
	}
	return reservedSockets{}, ErrInvalidPeerConfig
}

func (sockets reservedSockets) close() {
	if sockets.quic != nil {
		_ = sockets.quic.Close()
	}
	if sockets.wss != nil {
		_ = sockets.wss.Close()
	}
	if sockets.tcp != nil {
		_ = sockets.tcp.Close()
	}
}

func randomCarrierPorts() ([3]uint16, error) {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return [3]uint16{}, err
	}
	span := uint32(MaxCarrierPort-MinCarrierPort) + 1
	values := [3]uint16{
		MinCarrierPort + uint16((uint32(raw[0])<<8|uint32(raw[1]))%span),
		MinCarrierPort + uint16((uint32(raw[2])<<8|uint32(raw[3]))%span),
		MinCarrierPort + uint16((uint32(raw[4])<<8|uint32(raw[5]))%span),
	}
	if values[0] == values[1] || values[0] == values[2] || values[1] == values[2] {
		return randomCarrierPorts()
	}
	return values, nil
}

func makePeerTLSConfig(
	identity *PeerIdentity,
	clientArtifacts ClientPublicArtifacts,
	runID string,
) (*tls.Config, error) {
	if identity == nil {
		return nil, ErrInvalidPeerConfig
	}
	ca, err := x509.ParseCertificate(identity.CADER)
	if err != nil {
		return nil, ErrInvalidPeerConfig
	}
	clientCertificate, err := x509.ParseCertificate(identity.ClientCertificateDER)
	if err != nil ||
		clientCertificate.Subject.CommonName != clientCertificateIdentity(runID) {
		return nil, ErrInvalidPeerConfig
	}
	clientPool := x509.NewCertPool()
	clientPool.AddCert(ca)
	expectedClientDER := append([]byte(nil), identity.ClientCertificateDER...)
	config := &tls.Config{
		Certificates: []tls.Certificate{identity.ServerTLSCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.Version != tls.VersionTLS13 ||
				len(state.PeerCertificates) != 1 ||
				!bytes.Equal(state.PeerCertificates[0].Raw, expectedClientDER) ||
				state.PeerCertificates[0].Subject.CommonName != clientCertificateIdentity(runID) {
				return ErrInvalidIdentity
			}
			return nil
		},
	}
	_ = clientArtifacts
	return config, nil
}

func configureExternalPeer(
	wireGuard *device.Device,
	privateKey []byte,
	clientPublicKey []byte,
) error {
	if wireGuard == nil || len(privateKey) != 32 || len(clientPublicKey) != 32 {
		return ErrInvalidPeerConfig
	}
	configuration := fmt.Sprintf(
		"private_key=%s\nreplace_peers=true\npublic_key=%s\nprotocol_version=1\nreplace_allowed_ips=true\nallowed_ip=%s/32\nendpoint=%s\n",
		hex.EncodeToString(privateKey),
		hex.EncodeToString(clientPublicKey),
		InnerClientIPv4,
		carrierEndpointID,
	)
	if err := wireGuard.IpcSet(configuration); err != nil {
		return fmt.Errorf("configure external peer: %w", err)
	}
	return nil
}

func verifyLocalSystemSSH(ctx context.Context) error {
	checkContext, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
	}
	connection, err := dialer.DialContext(checkContext, "tcp4", "127.0.0.1:22")
	if err != nil {
		return fmt.Errorf("%w: fixed OpenSSH target unavailable", ErrSSHProof)
	}
	return connection.Close()
}

type controlledPacketConn struct {
	net.PacketConn
	blocked atomic.Bool
	dropped atomic.Uint64
}

func (connection *controlledPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	for {
		count, address, err := connection.PacketConn.ReadFrom(buffer)
		if err != nil {
			return count, address, err
		}
		if connection.blocked.Load() {
			connection.dropped.Add(1)
			continue
		}
		return count, address, nil
	}
}

func newManagedCarrier(transport profile.Transport, value carrier.Carrier) *managedCarrier {
	return &managedCarrier{
		Carrier:   value,
		transport: transport,
		closed:    make(chan struct{}),
	}
}

func acceptContext(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type result struct {
		connection net.Conn
		err        error
	}
	results := make(chan result, 1)
	go func() {
		connection, err := listener.Accept()
		results <- result{connection: connection, err: err}
	}()
	select {
	case value := <-results:
		return value.connection, value.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func attachPeerTransferManifest(runID string, artifacts *PeerPublicArtifacts) error {
	if artifacts == nil {
		return ErrInvalidArtifact
	}
	payloads := [][]byte{
		artifacts.Descriptor,
		artifacts.CADER,
		artifacts.ServerCertificateDER,
		artifacts.ClientCertificateDER,
		artifacts.OverlayServerPublicKey,
		artifacts.SystemSSHHostPublicKey,
	}
	files := make([]CourierFile, 0, len(payloads))
	for index, data := range payloads {
		file, err := NewCourierFile(PeerArtifactNames[index], data)
		if err != nil {
			return err
		}
		files = append(files, file)
	}
	manifest, err := EncodeTransferManifest(runID, CourierPeerToClient, files)
	if err != nil {
		return err
	}
	artifacts.TransferManifest = manifest
	return nil
}

func clonePeerArtifacts(value PeerPublicArtifacts) PeerPublicArtifacts {
	return PeerPublicArtifacts{
		Descriptor:             append([]byte(nil), value.Descriptor...),
		CADER:                  append([]byte(nil), value.CADER...),
		ServerCertificateDER:   append([]byte(nil), value.ServerCertificateDER...),
		ClientCertificateDER:   append([]byte(nil), value.ClientCertificateDER...),
		OverlayServerPublicKey: append([]byte(nil), value.OverlayServerPublicKey...),
		SystemSSHHostPublicKey: append([]byte(nil), value.SystemSSHHostPublicKey...),
		TransferManifest:       append([]byte(nil), value.TransferManifest...),
	}
}

func clearPeerArtifacts(value *PeerPublicArtifacts) {
	if value == nil {
		return
	}
	clear(value.Descriptor)
	clear(value.CADER)
	clear(value.ServerCertificateDER)
	clear(value.ClientCertificateDER)
	clear(value.OverlayServerPublicKey)
	clear(value.SystemSSHHostPublicKey)
	clear(value.TransferManifest)
	*value = PeerPublicArtifacts{}
}
