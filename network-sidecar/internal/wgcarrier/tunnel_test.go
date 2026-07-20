package wgcarrier

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

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
	serverResult := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer connection.Close()
		payload, readErr := io.ReadAll(io.LimitReader(connection, 4))
		if readErr == nil && string(payload) != "ping" {
			readErr = fmt.Errorf("unexpected tunneled payload: %q", payload)
		}
		if readErr == nil {
			_, readErr = connection.Write([]byte("pong"))
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
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("unexpected response: %q", response)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
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
