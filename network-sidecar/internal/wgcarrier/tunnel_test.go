package wgcarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
	quicgo "github.com/quic-go/quic-go"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type pairedCarrier struct {
	incoming chan []byte
	peer     *pairedCarrier
	closed   chan struct{}
}

func newCarrierPair() (*pairedCarrier, *pairedCarrier) {
	left := &pairedCarrier{incoming: make(chan []byte, 128), closed: make(chan struct{})}
	right := &pairedCarrier{incoming: make(chan []byte, 128), closed: make(chan struct{})}
	left.peer = right
	right.peer = left
	return left, right
}

func (carrier *pairedCarrier) Send(ctx context.Context, packet []byte) error {
	select {
	case carrier.peer.incoming <- append([]byte(nil), packet...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-carrier.closed:
		return net.ErrClosed
	case <-carrier.peer.closed:
		return net.ErrClosed
	}
}

func (carrier *pairedCarrier) Receive(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-carrier.incoming:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-carrier.closed:
		return nil, net.ErrClosed
	}
}

func (carrier *pairedCarrier) Close() error {
	select {
	case <-carrier.closed:
	default:
		close(carrier.closed)
	}
	return nil
}

func TestWireGuardEncryptsThroughKyClashCarrier(t *testing.T) {
	leftCarrier, rightCarrier := newCarrierPair()
	proveWireGuardTunnel(t, leftCarrier, rightCarrier)
}

func TestWireGuardEncryptsThroughFragmentedQUICCarrier(t *testing.T) {
	certificate, roots := tunnelCertificate(t)
	listener, err := quicgo.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"kyclash-network/1"},
	}, &quicgo.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan *carrier.QUIC, 1)
	serverError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		server, acceptErr := carrier.AcceptQUIC(connection)
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		serverResult <- server
	}()
	client, err := carrier.DialQUIC(context.Background(), carrier.QUICConfig{
		Address:    listener.Addr().String(),
		ServerName: "127.0.0.1",
		RootCAs:    roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server := <-serverResult:
		proveWireGuardTunnel(t, client, server)
	case err := <-serverError:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("QUIC server did not authenticate")
	}
}

func TestWireGuardEncryptsThroughTLSStreamCarrier(t *testing.T) {
	certificate, roots := tunnelCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan carrier.Carrier, 1)
	serverError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		if tlsConnection, ok := connection.(*tls.Conn); ok {
			if handshakeErr := tlsConnection.Handshake(); handshakeErr != nil {
				serverError <- handshakeErr
				return
			}
		}
		serverResult <- carrier.NewStream(connection)
	}()
	client, err := carrier.DialTCP(context.Background(), carrier.TCPConfig{
		Address:    listener.Addr().String(),
		ServerName: "127.0.0.1",
		RootCAs:    roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server := <-serverResult:
		proveWireGuardTunnel(t, client, server)
	case err := <-serverError:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("TCP lab server did not authenticate")
	}
}

func TestWireGuardEncryptsThroughWSSStreamCarrier(t *testing.T) {
	certificate, roots := tunnelCertificate(t)
	serverResult := make(chan carrier.Carrier, 1)
	serverError := make(chan error, 1)
	handlerDone := make(chan struct{})
	defer close(handlerDone)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connection, acceptErr := websocket.Accept(response, request, &websocket.AcceptOptions{
			CompressionMode: websocket.CompressionDisabled,
		})
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		serverResult <- carrier.NewStream(websocket.NetConn(context.Background(), connection, websocket.MessageBinary))
		<-handlerDone
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	client, err := carrier.DialWSS(context.Background(), carrier.WSSConfig{
		URL:     "wss" + strings.TrimPrefix(server.URL, "https"),
		RootCAs: roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case peer := <-serverResult:
		proveWireGuardTunnel(t, client, peer)
	case err := <-serverError:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("WSS lab server did not authenticate")
	}
}

func proveWireGuardTunnel(t *testing.T, leftCarrier, rightCarrier carrier.Carrier) {
	t.Helper()
	leftBind, err := NewBind(leftCarrier, "right")
	if err != nil {
		t.Fatal(err)
	}
	rightBind, err := NewBind(rightCarrier, "left")
	if err != nil {
		t.Fatal(err)
	}
	leftIP := netip.MustParseAddr("10.88.0.1")
	rightIP := netip.MustParseAddr("10.88.0.2")
	leftTUN, leftNet, err := netstack.CreateNetTUN([]netip.Addr{leftIP}, nil, 1_420)
	if err != nil {
		t.Fatal(err)
	}
	rightTUN, rightNet, err := netstack.CreateNetTUN([]netip.Addr{rightIP}, nil, 1_420)
	if err != nil {
		t.Fatal(err)
	}
	leftPrivate, leftPublic := testKeyPair(t)
	rightPrivate, rightPublic := testKeyPair(t)
	leftDevice := device.NewDevice(leftTUN, leftBind, device.NewLogger(device.LogLevelSilent, ""))
	rightDevice := device.NewDevice(rightTUN, rightBind, device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(leftDevice.Close)
	t.Cleanup(rightDevice.Close)
	configurePrivateKey(t, leftDevice, leftPrivate)
	configurePrivateKey(t, rightDevice, rightPrivate)
	configurePeer(t, rightDevice, leftPublic, "left", leftIP)
	configurePeer(t, leftDevice, rightPublic, "right", rightIP)
	if err := rightDevice.Up(); err != nil {
		t.Fatal(err)
	}
	if err := leftDevice.Up(); err != nil {
		t.Fatal(err)
	}
	listener, err := rightNet.ListenTCPAddrPort(netip.AddrPortFrom(rightIP, 8_080))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte("kyclash"), 715)
	serverResult := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer connection.Close()
		received := make([]byte, len(payload))
		_, readErr := io.ReadFull(connection, received)
		if readErr == nil && !bytes.Equal(received, payload) {
			readErr = fmt.Errorf("unexpected tunneled payload")
		}
		if readErr == nil {
			_, readErr = connection.Write(received)
		}
		serverResult <- readErr
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := leftNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(rightIP, 8_080))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("unexpected tunneled response")
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func tunnelCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}, roots
}

func testKeyPair(t *testing.T) (string, string) {
	t.Helper()
	private := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(private), hex.EncodeToString(public)
}

func configurePrivateKey(t *testing.T, wireGuard *device.Device, privateKey string) {
	t.Helper()
	if err := wireGuard.IpcSet("private_key=" + privateKey + "\n"); err != nil {
		t.Fatal(err)
	}
}

func configurePeer(t *testing.T, wireGuard *device.Device, peerPublicKey, endpointID string, allowedIP netip.Addr) {
	t.Helper()
	configuration := fmt.Sprintf(
		"replace_peers=true\npublic_key=%s\nprotocol_version=1\nreplace_allowed_ips=true\nallowed_ip=%s/32\nendpoint=%s\n",
		peerPublicKey,
		allowedIP,
		endpointID,
	)
	if err := wireGuard.IpcSet(configuration); err != nil {
		t.Fatal(err)
	}
}
