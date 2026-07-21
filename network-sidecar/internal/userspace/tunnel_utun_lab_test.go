//go:build darwin && kyclash_utun && kyclash_utun_lab

package userspace

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
	"github.com/kysion/kyclash/network-sidecar/internal/labserver"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/tun"
)

const utunLabConfirmation = "authorized-kyclash-virtualization-framework-vm"

func requireDisposableVirtualMac(t *testing.T) {
	t.Helper()
	if os.Getenv("KYCLASH_VM_LAB_CONFIRM") != utunLabConfirmation {
		t.Fatal("real utun lab requires the exact disposable-VM confirmation")
	}
	output, err := exec.Command("/usr/sbin/sysctl", "-n", "hw.model").Output()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(output)), "VirtualMac") {
		t.Fatal("real utun lab refuses non-VirtualMac hosts")
	}
}

func TestRealUTUNCreateOwnershipAndFinalAbsence(t *testing.T) {
	requireDisposableVirtualMac(t)
	for cycle := 0; cycle < 3; cycle++ {
		backend, networkProfile := realUTUNFixture(t, cycle)
		operation := "operation.utun.prepare"
		facts, err := backend.Prepare(context.Background(), networkProfile, operation)
		if err != nil {
			t.Fatalf("cycle %d prepare: %v", cycle, err)
		}
		if !validUTUNName(facts.InterfaceName) || facts.InstanceID != backend.instanceID || facts.OperationID != operation || facts.MTU != profile.TunnelMTU {
			t.Fatalf("cycle %d returned invalid ownership facts: %#v", cycle, facts)
		}
		assertInterfacePresent(t, facts.InterfaceName)
		if err := backend.Stop(context.Background()); err != nil {
			t.Fatalf("cycle %d stop: %v", cycle, err)
		}
		assertInterfaceAbsent(t, facts.InterfaceName)
		if err := backend.Close(); err != nil {
			t.Fatalf("cycle %d close: %v", cycle, err)
		}
	}
}

func TestRealUTUNCloseCleansPreparedDevice(t *testing.T) {
	requireDisposableVirtualMac(t)
	backend, networkProfile := realUTUNFixture(t, 9)
	facts, err := backend.Prepare(context.Background(), networkProfile, "operation.close.prepare")
	if err != nil {
		t.Fatal(err)
	}
	assertInterfacePresent(t, facts.InterfaceName)
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	assertInterfaceAbsent(t, facts.InterfaceName)
}

func TestRealUTUNCarrierSetupFailureCleansDevice(t *testing.T) {
	requireDisposableVirtualMac(t)
	backend, networkProfile := realUTUNFixture(t, 11)
	backend.dialer = func(context.Context, profile.Transport, profile.NormalizedEndpoint) (carrier.Carrier, error) {
		return nil, net.ErrClosed
	}
	facts, err := backend.Prepare(context.Background(), networkProfile, "operation.failure.prepare")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := networkProfile.Endpoint(profile.QUIC)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Connect(context.Background(), profile.QUIC, endpoint); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("carrier setup failure = %v", err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	assertInterfaceAbsent(t, facts.InterfaceName)
}

func TestRealUTUNCleanupNeverClaimsUnownedInterface(t *testing.T) {
	requireDisposableVirtualMac(t)
	unowned, err := tun.CreateTUN("utun", profile.TunnelMTU)
	if err != nil {
		t.Fatal(err)
	}
	unownedName, err := unowned.Name()
	if err != nil || !validUTUNName(unownedName) {
		_ = unowned.Close()
		t.Fatalf("unowned device name = %q, error = %v", unownedName, err)
	}
	defer func() {
		_ = unowned.Close()
		assertInterfaceAbsent(t, unownedName)
	}()
	backend, networkProfile := realUTUNFixture(t, 12)
	facts, err := backend.Prepare(context.Background(), networkProfile, "operation.owned.prepare")
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	assertInterfaceAbsent(t, facts.InterfaceName)
	assertInterfacePresent(t, unownedName)
}

func TestRealUTUNCarriesEncryptedLoopbackTraffic(t *testing.T) {
	requireDisposableVirtualMac(t)
	private := make([]byte, curve25519.ScalarSize)
	private[0], private[31] = 71, 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cluster, err := labserver.StartCluster(ctx, public)
	clear(public)
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	backend, err := New(private, cluster.Roots(), "instance.utun.traffic")
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	networkProfile := &profile.Profile{
		SchemaVersion: profile.SchemaVersion,
		ProfileID:     "utun.traffic.profile",
		ControlPlane:  "https://127.0.0.1/control",
		IdentityRef:   "keychain:net.kysion.kyclash.test.utun",
		Site:          profile.Site{ID: "utun-traffic", DisplayName: "utun traffic", PrivateCIDRs: []string{"10.88.0.2/32"}},
		Tunnel:        profile.Tunnel{LocalAddresses: []string{"10.88.0.1/24"}, PeerPublicKey: cluster.PeerPublicKey(), KeepaliveSeconds: 5},
		Transports:    profile.Transports{Primary: profile.QUIC, Fallbacks: []profile.Transport{profile.WSS, profile.TCP}, Endpoints: cluster.Endpoints()},
		Policy:        profile.Policy{ConnectTimeoutSeconds: 5, HealthIntervalSeconds: 1, FallbackThreshold: 1},
	}
	if err := networkProfile.Validate(); err != nil {
		t.Fatal(err)
	}
	facts, err := backend.Prepare(ctx, networkProfile, "operation.traffic.prepare")
	if err != nil {
		t.Fatal(err)
	}
	assertInterfacePresent(t, facts.InterfaceName)
	endpoint, err := networkProfile.Endpoint(profile.QUIC)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Connect(ctx, profile.QUIC, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := cluster.WaitReady(ctx, profile.QUIC); err != nil {
		t.Fatal(err)
	}
	ping := exec.CommandContext(ctx, "/sbin/ping", "-c", "3", "-W", "2000", "10.88.0.2")
	output, _ := ping.CombinedOutput()
	clear(output)
	state, err := backend.wireGuard.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	handshake := ipcMetric(state, "last_handshake_time_sec")
	transmitted := ipcMetric(state, "tx_bytes")
	received := ipcMetric(state, "rx_bytes")
	state = ""
	if handshake == 0 || transmitted == 0 || received == 0 {
		select {
		case serverErr := <-cluster.Done(profile.QUIC):
			t.Fatalf("encrypted utun traffic failed; QUIC lab server: %v", serverErr)
		default:
		}
		t.Fatalf("encrypted utun traffic counters did not advance")
	}
	if err := cluster.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := backend.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := backend.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	assertInterfaceAbsent(t, facts.InterfaceName)
}

func TestRealUTUNHoldForForcedTermination(t *testing.T) {
	requireDisposableVirtualMac(t)
	if os.Getenv("KYCLASH_UTUN_LAB_HOLD") != "1" {
		t.Skip("forced-termination fixture is enabled only by the disposable-VM harness")
	}
	ownerFile := os.Getenv("KYCLASH_UTUN_LAB_OWNER_FILE")
	if !strings.HasPrefix(filepath.Clean(ownerFile), "/var/tmp/kyclash-utun-lab-") {
		t.Fatal("owner evidence path must use the fixed disposable-VM prefix")
	}
	backend, networkProfile := realUTUNFixture(t, 27)
	defer backend.Close()
	facts, err := backend.Prepare(context.Background(), networkProfile, "operation.kill.prepare")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ownerFile, []byte(facts.InterfaceName+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {}
}

func ipcMetric(state, key string) uint64 {
	for line := range strings.SplitSeq(state, "\n") {
		name, value, ok := strings.Cut(line, "=")
		if ok && name == key {
			parsed, _ := strconv.ParseUint(value, 10, 64)
			return parsed
		}
	}
	return 0
}

func realUTUNFixture(t *testing.T, cycle int) (*Backend, *profile.Profile) {
	t.Helper()
	private := make([]byte, curve25519.ScalarSize)
	private[0] = byte(cycle + 1)
	private[31] = 64
	peerPrivate := make([]byte, curve25519.ScalarSize)
	peerPrivate[0] = byte(cycle + 17)
	peerPrivate[31] = 64
	peerPublic, err := curve25519.X25519(peerPrivate, curve25519.Basepoint)
	clear(peerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := New(private, nil, "instance.utun.lab")
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	networkProfile := &profile.Profile{
		SchemaVersion: profile.SchemaVersion,
		ProfileID:     "utun.lab.profile",
		ControlPlane:  "https://127.0.0.1/control",
		IdentityRef:   "keychain:net.kysion.kyclash.test.utun",
		Site:          profile.Site{ID: "utun-lab", DisplayName: "utun lab", PrivateCIDRs: []string{"10.127.0.0/16"}},
		Tunnel:        profile.Tunnel{LocalAddresses: []string{"10.89.0.1/32", "fd00:89::1/128"}, PeerPublicKey: base64.StdEncoding.EncodeToString(peerPublic), KeepaliveSeconds: 5},
		Transports:    profile.Transports{Primary: profile.QUIC, Fallbacks: []profile.Transport{profile.WSS, profile.TCP}, Endpoints: []profile.Endpoint{{Transport: profile.QUIC, URL: "https://127.0.0.1:443"}, {Transport: profile.WSS, URL: "wss://127.0.0.1:443/kynp"}, {Transport: profile.TCP, URL: "tcp://127.0.0.1:443"}}},
		Policy:        profile.Policy{ConnectTimeoutSeconds: 5, HealthIntervalSeconds: 1, FallbackThreshold: 1},
	}
	clear(peerPublic)
	if err := networkProfile.Validate(); err != nil {
		t.Fatal(err)
	}
	return backend, networkProfile
}

func assertInterfacePresent(t *testing.T, name string) {
	t.Helper()
	if output, err := exec.Command("/sbin/ifconfig", name).CombinedOutput(); err != nil {
		t.Fatalf("owned interface %s is absent: %s", name, output)
	}
}

func assertInterfaceAbsent(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := net.InterfaceByName(name); err != nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("owned interface %s remained after cleanup", name)
}
