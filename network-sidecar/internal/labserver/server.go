// Package labserver provides an in-process, loopback-only KyClash peer for
// deterministic carrier and userspace WireGuard integration tests.
package labserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/wgcarrier"
	quicgo "github.com/quic-go/quic-go"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	ErrNonLoopback = errors.New("lab server bind must be loopback")
	ErrUDPRefused  = errors.New("lab server UDP refusal enabled")
	ErrInvalid     = errors.New("invalid lab server configuration")
)

type Impairment struct {
	RefuseUDP               bool
	PacketDelay             time.Duration
	JitterStep              time.Duration
	RateLimitBytesPerSecond uint64
	DropEvery               uint64
	DuplicateEvery          uint64
	ReorderPairs            bool
	DisconnectAfter         uint64
}

type Config struct {
	Transport        profile.Transport
	BindHost         string
	ClientPublicKey  []byte
	ServerPrivateKey []byte
	AutoEcho         bool
	Impairment       Impairment
}

type Server struct {
	transport profile.Transport
	endpoint  profile.Endpoint
	roots     *x509.CertPool
	peerKey   string
	certDER   []byte
	listener  net.Listener
	quic      *quicgo.Listener
	http      *http.Server
	device    *device.Device
	network   *netstack.Net
	cancel    context.CancelFunc
	done      chan error
	ready     chan struct{}
	once      sync.Once
	echo      net.Listener
	autoEcho  bool
}

func Start(parent context.Context, config Config) (*Server, error) {
	if config.BindHost == "" {
		config.BindHost = "127.0.0.1"
	}
	host := net.ParseIP(config.BindHost)
	if host == nil || !host.IsLoopback() {
		return nil, ErrNonLoopback
	}
	if len(config.ClientPublicKey) != 32 || config.Impairment.PacketDelay < 0 || config.Impairment.JitterStep < 0 {
		return nil, ErrInvalid
	}
	if config.Transport == profile.QUIC && config.Impairment.RefuseUDP {
		return nil, ErrUDPRefused
	}
	certificate, roots, certDER, err := ephemeralCertificate(config.BindHost)
	if err != nil {
		return nil, err
	}
	private := append([]byte(nil), config.ServerPrivateKey...)
	var public []byte
	if len(private) == 0 {
		private, public, err = keyPair()
	} else if len(private) == 32 {
		public, err = curve25519.X25519(private, curve25519.Basepoint)
	} else {
		err = ErrInvalid
	}
	if err != nil {
		clear(private)
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	server := &Server{transport: config.Transport, roots: roots, peerKey: base64.StdEncoding.EncodeToString(public), certDER: certDER, cancel: cancel, done: make(chan error, 1), ready: make(chan struct{}), autoEcho: config.AutoEcho}
	accept, err := server.listen(config.BindHost, certificate)
	if err != nil {
		cancel()
		clear(private)
		return nil, err
	}
	clientPublic := append([]byte(nil), config.ClientPublicKey...)
	go server.run(ctx, accept, private, clientPublic, config.Impairment)
	return server, nil
}

func (server *Server) Endpoint() profile.Endpoint { return server.endpoint }
func (server *Server) Roots() *x509.CertPool      { return server.roots.Clone() }
func (server *Server) PeerPublicKey() string      { return server.peerKey }
func (server *Server) CertificateDER() []byte     { return append([]byte(nil), server.certDER...) }
func (server *Server) Network() *netstack.Net     { return server.network }
func (server *Server) Done() <-chan error         { return server.done }
func (server *Server) WaitReady(ctx context.Context) error {
	select {
	case <-server.ready:
		return nil
	case err := <-server.done:
		if err == nil {
			return net.ErrClosed
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (server *Server) Close() error {
	server.once.Do(func() {
		server.cancel()
		if server.http != nil {
			_ = server.http.Close()
		}
		if server.listener != nil {
			_ = server.listener.Close()
		}
		if server.quic != nil {
			_ = server.quic.Close()
		}
		if server.device != nil {
			server.device.Close()
		}
		if server.echo != nil {
			_ = server.echo.Close()
		}
	})
	return nil
}

type acceptCarrier func(context.Context) (carrier.Carrier, error)

func (server *Server) listen(host string, certificate tls.Certificate) (acceptCarrier, error) {
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	address := net.JoinHostPort(host, "0")
	switch server.transport {
	case profile.QUIC:
		quicTLS := tlsConfig.Clone()
		quicTLS.NextProtos = []string{"kyclash-network/1"}
		listener, err := quicgo.ListenAddr(address, quicTLS, &quicgo.Config{EnableDatagrams: true})
		if err != nil {
			return nil, err
		}
		server.quic = listener
		server.endpoint = profile.Endpoint{Transport: profile.QUIC, URL: "https://" + listener.Addr().String()}
		return func(ctx context.Context) (carrier.Carrier, error) {
			connection, err := listener.Accept(ctx)
			if err != nil {
				return nil, err
			}
			return carrier.AcceptQUIC(connection)
		}, nil
	case profile.TCP:
		listener, err := tls.Listen("tcp", address, tlsConfig)
		if err != nil {
			return nil, err
		}
		server.listener = listener
		server.endpoint = profile.Endpoint{Transport: profile.TCP, URL: "tcp://" + listener.Addr().String()}
		return func(ctx context.Context) (carrier.Carrier, error) {
			connection, err := acceptContext(ctx, listener)
			if err != nil {
				return nil, err
			}
			if err := connection.(*tls.Conn).HandshakeContext(ctx); err != nil {
				_ = connection.Close()
				return nil, err
			}
			return carrier.NewStream(connection), nil
		}, nil
	case profile.WSS:
		listener, err := tls.Listen("tcp", address, tlsConfig)
		if err != nil {
			return nil, err
		}
		accepted := make(chan carrier.Carrier, 1)
		handlerErrors := make(chan error, 1)
		mux := http.NewServeMux()
		mux.HandleFunc("/kynp", func(response http.ResponseWriter, request *http.Request) {
			connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
			if err != nil {
				select {
				case handlerErrors <- err:
				default:
				}
				return
			}
			select {
			case accepted <- carrier.NewStream(websocket.NetConn(context.Background(), connection, websocket.MessageBinary)):
			case <-request.Context().Done():
				_ = connection.Close(websocket.StatusGoingAway, "closed")
			}
		})
		server.listener = listener
		server.http = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = server.http.Serve(listener) }()
		server.endpoint = profile.Endpoint{Transport: profile.WSS, URL: "wss://" + listener.Addr().String() + "/kynp"}
		return func(ctx context.Context) (carrier.Carrier, error) {
			select {
			case value := <-accepted:
				return value, nil
			case err := <-handlerErrors:
				return nil, err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}, nil
	default:
		return nil, ErrInvalid
	}
}

func (server *Server) run(ctx context.Context, accept acceptCarrier, private, clientPublic []byte, impairment Impairment) {
	defer clear(private)
	defer clear(clientPublic)
	packetCarrier, err := accept(ctx)
	if err != nil {
		server.finish(ctx, err)
		return
	}
	packetCarrier = &impairedCarrier{Carrier: packetCarrier, impairment: impairment}
	bind, err := wgcarrier.NewBind(packetCarrier, "kyclash-client")
	if err != nil {
		_ = packetCarrier.Close()
		server.finish(ctx, err)
		return
	}
	tunnel, network, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.88.0.2")}, nil, profile.TunnelMTU)
	if err != nil {
		_ = packetCarrier.Close()
		server.finish(ctx, err)
		return
	}
	wireGuard := device.NewDevice(tunnel, bind, device.NewLogger(device.LogLevelSilent, ""))
	server.device, server.network = wireGuard, network
	configuration := fmt.Sprintf("private_key=%s\nreplace_peers=true\npublic_key=%s\nprotocol_version=1\nreplace_allowed_ips=true\nallowed_ip=10.88.0.1/32\nendpoint=kyclash-client\n", hex.EncodeToString(private), hex.EncodeToString(clientPublic))
	if err = wireGuard.IpcSet(configuration); err == nil {
		err = wireGuard.Up()
	}
	if err != nil {
		wireGuard.Close()
		server.finish(ctx, err)
		return
	}
	if server.autoEcho {
		server.echo, err = network.ListenTCPAddrPort(netip.MustParseAddrPort(ProbeAddress))
		if err != nil {
			wireGuard.Close()
			server.finish(ctx, err)
			return
		}
		go echoLoop(ctx, server.echo)
	}
	close(server.ready)
	<-ctx.Done()
	wireGuard.Close()
	server.finish(ctx, nil)
}

func (server *Server) finish(ctx context.Context, err error) {
	if err != nil && ctx.Err() != nil {
		err = nil
	}
	select {
	case server.done <- err:
	default:
	}
}

type impairedCarrier struct {
	carrier.Carrier
	impairment Impairment
	mu         sync.Mutex
	packets    uint64
	held       []byte
}

func (value *impairedCarrier) Send(ctx context.Context, packet []byte) error {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.packets++
	count := value.packets
	if value.impairment.DisconnectAfter != 0 && count > value.impairment.DisconnectAfter {
		_ = value.Close()
		return net.ErrClosed
	}
	delay := value.impairment.PacketDelay
	if value.impairment.JitterStep != 0 {
		delay += time.Duration((count-1)%3) * value.impairment.JitterStep
	}
	if value.impairment.RateLimitBytesPerSecond != 0 {
		delay += time.Duration((uint64(len(packet))*uint64(time.Second) + value.impairment.RateLimitBytesPerSecond - 1) / value.impairment.RateLimitBytesPerSecond)
	}
	if delay != 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if value.impairment.DropEvery != 0 && count%value.impairment.DropEvery == 0 {
		return nil
	}
	if value.impairment.ReorderPairs {
		if count%2 == 1 {
			value.held = append(value.held[:0], packet...)
			return nil
		}
		if err := value.Carrier.Send(ctx, packet); err != nil {
			return err
		}
		if len(value.held) != 0 {
			held := append([]byte(nil), value.held...)
			clear(value.held)
			value.held = nil
			if err := value.Carrier.Send(ctx, held); err != nil {
				return err
			}
		}
	} else if err := value.Carrier.Send(ctx, packet); err != nil {
		return err
	}
	if value.impairment.DuplicateEvery != 0 && count%value.impairment.DuplicateEvery == 0 {
		return value.Carrier.Send(ctx, packet)
	}
	return nil
}

func acceptContext(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type result struct {
		connection net.Conn
		err        error
	}
	results := make(chan result, 1)
	go func() { connection, err := listener.Accept(); results <- result{connection, err} }()
	select {
	case value := <-results:
		return value.connection, value.err
	case <-ctx.Done():
		_ = listener.Close()
		return nil, ctx.Err()
	}
}

func ephemeralCertificate(host string) (tls.Certificate, *x509.CertPool, []byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, roots, append([]byte(nil), der...), nil
}

func keyPair() ([]byte, []byte, error) {
	private := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(private); err != nil {
		return nil, nil, err
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		clear(private)
		return nil, nil, err
	}
	return private, public, nil
}

// Host returns the normalized endpoint host for assertions without exposing
// certificate or key material.
func (server *Server) Host() string {
	parsed, _ := url.Parse(server.endpoint.URL)
	return strings.Trim(parsed.Hostname(), "[]")
}
