package labserver

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/wgcarrier"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestRejectsUnsafeConfiguration(t *testing.T) {
	_, public, err := keyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"0.0.0.0", "192.0.2.1", "example.test"} {
		_, err := Start(context.Background(), Config{Transport: profile.TCP, BindHost: host, ClientPublicKey: public})
		if !errors.Is(err, ErrNonLoopback) {
			t.Fatalf("host %q: got %v", host, err)
		}
	}
	_, err = Start(context.Background(), Config{Transport: profile.QUIC, ClientPublicKey: public, Impairment: Impairment{RefuseUDP: true}})
	if !errors.Is(err, ErrUDPRefused) {
		t.Fatalf("got %v", err)
	}
}

func TestEphemeralIdentityChangesEveryRun(t *testing.T) {
	_, public, err := keyPair()
	if err != nil {
		t.Fatal(err)
	}
	first, err := Start(context.Background(), Config{Transport: profile.TCP, ClientPublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Start(context.Background(), Config{Transport: profile.TCP, ClientPublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.PeerPublicKey() == second.PeerPublicKey() {
		t.Fatal("WireGuard identity was reused")
	}
	if first.Host() != "127.0.0.1" || second.Host() != "127.0.0.1" {
		t.Fatal("server escaped loopback")
	}
}

func TestTLSIdentityMismatch(t *testing.T) {
	_, public, err := keyPair()
	if err != nil {
		t.Fatal(err)
	}
	server, err := Start(context.Background(), Config{Transport: profile.TCP, ClientPublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	parsed, _ := url.Parse(server.Endpoint().URL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = carrier.DialTCP(ctx, carrier.TCPConfig{Address: parsed.Host, ServerName: parsed.Hostname(), RootCAs: x509.NewCertPool(), Timeout: time.Second})
	if err == nil {
		t.Fatal("untrusted ephemeral certificate was accepted")
	}
}

func TestDeterministicLossDisconnectAndAbort(t *testing.T) {
	base := &recordingCarrier{}
	impaired := &impairedCarrier{Carrier: base, impairment: Impairment{DropEvery: 2, DisconnectAfter: 3}}
	for index := 1; index <= 3; index++ {
		if err := impaired.Send(context.Background(), []byte{byte(index)}); err != nil {
			t.Fatalf("packet %d: %v", index, err)
		}
	}
	if len(base.sent) != 2 || base.sent[0][0] != 1 || base.sent[1][0] != 3 {
		t.Fatalf("unexpected deterministic delivery: %v", base.sent)
	}
	if err := impaired.Send(context.Background(), []byte{4}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected forced disconnect, got %v", err)
	}

	_, public, err := keyPair()
	if err != nil {
		t.Fatal(err)
	}
	server, err := Start(context.Background(), Config{Transport: profile.TCP, ClientPublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-server.Done():
		if err != nil {
			t.Fatalf("abort cleanup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server abort did not cancel accept")
	}
}

func TestDeterministicDuplicateReorderJitterAndRateLimit(t *testing.T) {
	base := &recordingCarrier{}
	impaired := &impairedCarrier{Carrier: base, impairment: Impairment{
		DuplicateEvery:          2,
		ReorderPairs:            true,
		JitterStep:              time.Millisecond,
		RateLimitBytesPerSecond: 10_000,
	}}
	started := time.Now()
	for index := 1; index <= 4; index++ {
		if err := impaired.Send(context.Background(), []byte{byte(index)}); err != nil {
			t.Fatalf("packet %d: %v", index, err)
		}
	}
	want := []byte{2, 1, 2, 4, 3, 4}
	if len(base.sent) != len(want) {
		t.Fatalf("delivery count = %d, want %d: %v", len(base.sent), len(want), base.sent)
	}
	for index, packet := range base.sent {
		if len(packet) != 1 || packet[0] != want[index] {
			t.Fatalf("delivery %d = %v, want %d", index, packet, want[index])
		}
	}
	if elapsed := time.Since(started); elapsed < 3*time.Millisecond {
		t.Fatalf("deterministic jitter/rate delay was not applied: %v", elapsed)
	}
}

func TestBidirectionalWireGuardTrafficAcrossCarriers(t *testing.T) {
	for _, transport := range []profile.Transport{profile.QUIC, profile.WSS, profile.TCP} {
		t.Run(string(transport), func(t *testing.T) { proveTunnel(t, transport) })
	}
}

func proveTunnel(t *testing.T, transport profile.Transport) {
	t.Helper()
	clientPrivate, clientPublic, err := keyPair()
	if err != nil {
		t.Fatal(err)
	}
	server, err := Start(context.Background(), Config{Transport: transport, ClientPublicKey: clientPublic, Impairment: Impairment{PacketDelay: time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	packetCarrier, err := dial(context.Background(), server)
	if err != nil {
		t.Fatal(err)
	}
	bind, err := wgcarrier.NewBind(packetCarrier, "kyclash-server")
	if err != nil {
		t.Fatal(err)
	}
	tunnel, clientNetwork, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.88.0.1")}, nil, profile.TunnelMTU)
	if err != nil {
		t.Fatal(err)
	}
	clientDevice := device.NewDevice(tunnel, bind, device.NewLogger(device.LogLevelSilent, ""))
	defer clientDevice.Close()
	peer, err := serverPeerHex(server.PeerPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	configuration := fmt.Sprintf("private_key=%s\nreplace_peers=true\npublic_key=%s\nprotocol_version=1\nreplace_allowed_ips=true\nallowed_ip=10.88.0.2/32\nendpoint=kyclash-server\n", hex.EncodeToString(clientPrivate), peer)
	clear(clientPrivate)
	if err := clientDevice.IpcSet(configuration); err != nil {
		t.Fatal(err)
	}
	if err := clientDevice.Up(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), tunnelProofTimeout)
	defer cancel()
	if err := server.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	listener, err := server.Network().ListenTCPAddrPort(netip.MustParseAddrPort("10.88.0.2:8080"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErrors := make(chan error, 1)
	go echoConnections(listener, 4, serverErrors)
	for index := 0; index < 4; index++ {
		connection, err := clientNetwork.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.88.0.2:8080"))
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{byte(index + 1)}, 4096+index*733)
		if _, err = connection.Write(payload); err == nil {
			response := make([]byte, len(payload))
			_, err = io.ReadFull(connection, response)
			if err == nil && !bytes.Equal(response, payload) {
				err = errors.New("echo mismatch")
			}
		}
		_ = connection.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

func echoConnections(listener net.Listener, count int, result chan<- error) {
	for index := 0; index < count; index++ {
		connection, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		_, err = io.Copy(connection, connection)
		_ = connection.Close()
		if err != nil {
			result <- err
			return
		}
	}
	result <- nil
}

func dial(ctx context.Context, server *Server) (carrier.Carrier, error) {
	parsed, err := url.Parse(server.Endpoint().URL)
	if err != nil {
		return nil, err
	}
	switch server.Endpoint().Transport {
	case profile.QUIC:
		return carrier.DialQUIC(ctx, carrier.QUICConfig{Address: parsed.Host, ServerName: parsed.Hostname(), RootCAs: server.Roots(), Timeout: 5 * time.Second})
	case profile.WSS:
		return carrier.DialWSS(ctx, carrier.WSSConfig{URL: parsed.String(), RootCAs: server.Roots(), Timeout: 5 * time.Second})
	case profile.TCP:
		return carrier.DialTCP(ctx, carrier.TCPConfig{Address: parsed.Host, ServerName: parsed.Hostname(), RootCAs: server.Roots(), Timeout: 5 * time.Second})
	default:
		return nil, ErrInvalid
	}
}

func serverPeerHex(encoded string) (string, error) {
	decoded, err := profile.Profile{Tunnel: profile.Tunnel{PeerPublicKey: encoded}}.PeerKeyBytes()
	if err != nil {
		return "", err
	}
	defer clear(decoded)
	return hex.EncodeToString(decoded), nil
}

type recordingCarrier struct {
	sent   [][]byte
	closed bool
}

func (value *recordingCarrier) Send(_ context.Context, packet []byte) error {
	value.sent = append(value.sent, append([]byte(nil), packet...))
	return nil
}
func (value *recordingCarrier) Receive(context.Context) ([]byte, error) { return nil, net.ErrClosed }
func (value *recordingCarrier) Close() error                            { value.closed = true; return nil }
