package userspace

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
	"github.com/kysion/kyclash/network-sidecar/internal/frame"
	"github.com/kysion/kyclash/network-sidecar/internal/ipc"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/wgcarrier"
)

type memoryCarrier struct {
	closed        chan struct{}
	once          sync.Once
	probeMu       sync.Mutex
	probeLatency  []time.Duration
	probeFailures []error
	probeCalls    int
}

type packetOnlyCarrier struct {
	inner *memoryCarrier
}

func (value *packetOnlyCarrier) Send(ctx context.Context, packet []byte) error {
	return value.inner.Send(ctx, packet)
}

func (value *packetOnlyCarrier) Receive(ctx context.Context) ([]byte, error) {
	return value.inner.Receive(ctx)
}

func (value *packetOnlyCarrier) Close() error { return value.inner.Close() }

type blockingProbeCarrier struct {
	*memoryCarrier
	started chan struct{}
	once    sync.Once
}

type dropPongConnection struct {
	net.Conn
	mu       sync.Mutex
	dropAt   int
	pongSeen int
}

func (connection *dropPongConnection) Write(packet []byte) (int, error) {
	decoded, err := frame.Decode(bytes.NewReader(packet))
	if err == nil && decoded.Kind == frame.KindPong {
		connection.mu.Lock()
		connection.pongSeen++
		drop := connection.pongSeen == connection.dropAt
		connection.mu.Unlock()
		if drop {
			return len(packet), nil
		}
	}
	return connection.Conn.Write(packet)
}

func (value *blockingProbeCarrier) Probe(ctx context.Context) (time.Duration, error) {
	value.once.Do(func() { close(value.started) })
	<-ctx.Done()
	return 0, ctx.Err()
}

func newMemoryCarrier() *memoryCarrier {
	return &memoryCarrier{closed: make(chan struct{})}
}

func (*memoryCarrier) Send(context.Context, []byte) error { return nil }
func (memory *memoryCarrier) Receive(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-memory.closed:
		return nil, net.ErrClosed
	}
}
func (memory *memoryCarrier) Close() error {
	memory.once.Do(func() { close(memory.closed) })
	return nil
}
func (memory *memoryCarrier) Probe(ctx context.Context) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	memory.probeMu.Lock()
	defer memory.probeMu.Unlock()
	index := memory.probeCalls
	memory.probeCalls++
	if index < len(memory.probeFailures) && memory.probeFailures[index] != nil {
		return 0, memory.probeFailures[index]
	}
	if index < len(memory.probeLatency) {
		return memory.probeLatency[index], nil
	}
	return time.Millisecond, nil
}

func testProfile(t *testing.T) *profile.Profile {
	t.Helper()
	fixture, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := profile.Decode(fixture)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func connectedBackend(t *testing.T, packetCarrier carrier.Carrier) *Backend {
	t.Helper()
	backend, err := New(make([]byte, 32), nil, "instance.test")
	if err != nil {
		t.Fatal(err)
	}
	backend.dialer = func(context.Context, profile.Transport, profile.NormalizedEndpoint) (carrier.Carrier, error) {
		return packetCarrier, nil
	}
	networkProfile := testProfile(t)
	if _, err := backend.Prepare(context.Background(), networkProfile, "request.prepare"); err != nil {
		t.Fatal(err)
	}
	endpoint, err := networkProfile.Endpoint(profile.QUIC)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Connect(context.Background(), profile.QUIC, endpoint); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

func TestLabWireGuardStatsAreLimitedToPreparedLabBackend(t *testing.T) {
	ordinary, err := New(make([]byte, 32), nil, "instance.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ordinary.Prepare(context.Background(), testProfile(t), "request.prepare"); err != nil {
		t.Fatal(err)
	}
	if _, err := ordinary.LabWireGuardStats(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("ordinary backend exposed lab stats: %v", err)
	}
	_ = ordinary.Close()

	lab, err := NewLab(make([]byte, 32), nil, netip.MustParseAddrPort("10.88.0.2:8080"), "instance.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lab.LabWireGuardStats(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("unprepared lab backend exposed stats: %v", err)
	}
	if _, err := lab.Prepare(context.Background(), testProfile(t), "request.lab.stats"); err != nil {
		t.Fatal(err)
	}
	stats, err := lab.LabWireGuardStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.LastHandshakeSec == "" || stats.LastHandshakeNSec == "" || stats.RXBytes == "" || stats.TXBytes == "" {
		t.Fatalf("lab stats omitted expected counters: %#v", stats)
	}
	if err := lab.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lab.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBackendPreparesConnectsAndReconnectsExplicitCarriers(t *testing.T) {
	backend, err := New(make([]byte, 32), nil, "instance.test")
	if err != nil {
		t.Fatal(err)
	}
	var selected []profile.Transport
	backend.dialer = func(_ context.Context, transport profile.Transport, _ profile.NormalizedEndpoint) (carrier.Carrier, error) {
		selected = append(selected, transport)
		return newMemoryCarrier(), nil
	}
	facts, err := backend.Prepare(context.Background(), testProfile(t), "request.prepare")
	if err != nil {
		t.Fatal(err)
	}
	if facts.InterfaceName != "userspace" || facts.MTU != profile.TunnelMTU || facts.InstanceID != "instance.test" || facts.OperationID != "request.prepare" || !facts.HasIPv4 || !facts.HasIPv6 {
		t.Fatalf("unexpected redacted device facts: %#v", facts)
	}
	if backend.privateKey != nil {
		t.Fatal("private key remained owned after WireGuard configuration")
	}
	for _, transport := range []profile.Transport{profile.QUIC, profile.WSS, profile.TCP} {
		endpoint, endpointErr := testProfile(t).Endpoint(transport)
		if endpointErr != nil {
			t.Fatal(endpointErr)
		}
		if err := backend.Connect(context.Background(), transport, endpoint); err != nil {
			t.Fatal(err)
		}
		health, err := backend.Health(context.Background())
		if err != nil || !health.Reachable {
			t.Fatalf("unexpected health: %#v %v", health, err)
		}
		if err := backend.Disconnect(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(selected) != 3 || selected[0] != profile.QUIC || selected[1] != profile.WSS || selected[2] != profile.TCP {
		t.Fatalf("backend changed explicit carrier order: %v", selected)
	}
	if err := backend.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMutualTLSBackendOwnsCertificateThroughFallbackUntilClose(t *testing.T) {
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{{1, 2, 3, 4}},
		PrivateKey:  clientPrivate,
	}
	backend, err := NewLabWithMutualTLS(
		make([]byte, 32),
		nil,
		MutualTLSConfig{ClientCertificate: certificate, ExactTLS13: true},
		netip.MustParseAddrPort("10.88.0.2:8080"),
		"instance.mutual-tls",
	)
	if err != nil {
		t.Fatal(err)
	}
	originalCertificateByte := certificate.Certificate[0][0]
	originalPrivateKeyByte := clientPrivate[0]
	clear(certificate.Certificate[0])
	clear(clientPrivate)
	if backend.mutualTLS == nil ||
		backend.mutualTLS.ClientCertificate.Certificate[0][0] != originalCertificateByte ||
		backend.mutualTLS.ClientCertificate.PrivateKey.(ed25519.PrivateKey)[0] != originalPrivateKeyByte ||
		!backend.mutualTLS.ExactTLS13 {
		t.Fatal("backend did not take an independent copy of the mutual TLS identity")
	}

	backend.dialer = func(_ context.Context, _ profile.Transport, _ profile.NormalizedEndpoint) (carrier.Carrier, error) {
		return newMemoryCarrier(), nil
	}
	networkProfile := testProfile(t)
	if _, err := backend.Prepare(context.Background(), networkProfile, "request.prepare.mutual-tls"); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []profile.Transport{profile.QUIC, profile.WSS, profile.TCP} {
		endpoint, endpointErr := networkProfile.Endpoint(transport)
		if endpointErr != nil {
			t.Fatal(endpointErr)
		}
		if err := backend.Connect(context.Background(), transport, endpoint); err != nil {
			t.Fatal(err)
		}
		if backend.mutualTLS == nil {
			t.Fatalf("mutual TLS identity was released while %s was active", transport)
		}
		if err := backend.Disconnect(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if err := backend.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if backend.mutualTLS == nil {
		t.Fatal("mutual TLS identity was released before backend Close")
	}
	retainedCertificate := &backend.mutualTLS.ClientCertificate
	retainedPrivateKey := retainedCertificate.PrivateKey.(ed25519.PrivateKey)
	retainedDER := retainedCertificate.Certificate[0]
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	if backend.mutualTLS != nil {
		t.Fatal("mutual TLS identity remained retained after backend Close")
	}
	if retainedCertificate.PrivateKey != nil || retainedCertificate.Certificate != nil {
		t.Fatal("retained mutual TLS certificate was not released")
	}
	if !bytes.Equal(retainedPrivateKey, make([]byte, len(retainedPrivateKey))) ||
		!bytes.Equal(retainedDER, make([]byte, len(retainedDER))) {
		t.Fatal("retained mutual TLS key or certificate bytes were not cleared")
	}
}

func TestMutualTLSBackendConfigFailsClosed(t *testing.T) {
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []MutualTLSConfig{
		{},
		{ClientCertificate: tls.Certificate{Certificate: [][]byte{{1}}}},
		{ClientCertificate: tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: struct{}{}}},
	} {
		backend, err := NewWithMutualTLS(make([]byte, 32), nil, config, "instance.invalid-mutual-tls")
		if backend != nil || !errors.Is(err, ErrInvalidState) {
			t.Fatalf("expected invalid mutual TLS config refusal, got backend=%v err=%v", backend, err)
		}
	}
	backend, err := NewLabWithMutualTLS(
		make([]byte, 32),
		nil,
		MutualTLSConfig{ClientCertificate: tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: clientPrivate}},
		netip.AddrPort{},
		"instance.invalid-mutual-tls-probe",
	)
	if backend != nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected invalid probe refusal, got backend=%v err=%v", backend, err)
	}
}

func TestOrdinaryBackendDoesNotOptIntoMutualTLS(t *testing.T) {
	backend, err := New(make([]byte, 32), nil, "instance.ordinary")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if backend.mutualTLS != nil {
		t.Fatal("ordinary backend unexpectedly retained a client certificate")
	}
}

func TestBackendConvergesAfterRepeatedReconnectCycles(t *testing.T) {
	backend, err := New(make([]byte, 32), nil, "instance.test")
	if err != nil {
		t.Fatal(err)
	}
	backend.dialer = func(_ context.Context, _ profile.Transport, _ profile.NormalizedEndpoint) (carrier.Carrier, error) {
		return newMemoryCarrier(), nil
	}
	networkProfile := testProfile(t)
	if _, err := backend.Prepare(context.Background(), networkProfile, "request.prepare"); err != nil {
		t.Fatal(err)
	}
	endpoint, err := networkProfile.Endpoint(profile.TCP)
	if err != nil {
		t.Fatal(err)
	}
	for cycle := 0; cycle < 12; cycle++ {
		if err := backend.Connect(context.Background(), profile.TCP, endpoint); err != nil {
			t.Fatalf("cycle %d connect: %v", cycle, err)
		}
		if backend.active != profile.TCP {
			t.Fatalf("cycle %d did not record active transport", cycle)
		}
		if err := backend.Disconnect(context.Background()); err != nil {
			t.Fatalf("cycle %d disconnect: %v", cycle, err)
		}
		if backend.active != "" || backend.operationCancel.Load() != nil {
			t.Fatalf("cycle %d left carrier state attached: active=%q cancel=%v", cycle, backend.active, backend.operationCancel.Load() != nil)
		}
	}
	if err := backend.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBackendDialFailureDoesNotAttachCarrier(t *testing.T) {
	backend, err := New(make([]byte, 32), nil, "instance.test")
	if err != nil {
		t.Fatal(err)
	}
	backend.dialer = func(context.Context, profile.Transport, profile.NormalizedEndpoint) (carrier.Carrier, error) {
		return nil, errors.New("injected dial failure")
	}
	networkProfile := testProfile(t)
	if _, err := backend.Prepare(context.Background(), networkProfile, "request.prepare"); err != nil {
		t.Fatal(err)
	}
	endpoint, err := networkProfile.Endpoint(profile.QUIC)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Connect(context.Background(), profile.QUIC, endpoint); err == nil || backend.active != "" {
		t.Fatal("dial failure activated a carrier")
	}
	_ = backend.Close()
}

func TestBackendCancellationInterruptsDialWithoutActivatingCarrier(t *testing.T) {
	backend, err := New(make([]byte, 32), nil, "instance.test")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	backend.dialer = func(ctx context.Context, _ profile.Transport, _ profile.NormalizedEndpoint) (carrier.Carrier, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	networkProfile := testProfile(t)
	if _, err := backend.Prepare(context.Background(), networkProfile, "request.prepare"); err != nil {
		t.Fatal(err)
	}
	endpoint, err := networkProfile.Endpoint(profile.QUIC)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	connectContext, cancelConnect := context.WithCancel(context.Background())
	go func() { result <- backend.Connect(connectContext, profile.QUIC, endpoint) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	cancelConnect()
	if err := <-result; !errors.Is(err, context.Canceled) || backend.active != "" {
		t.Fatalf("cancel did not preserve disconnected carrier state: %v", err)
	}
	_ = backend.Close()
}

func TestBackendHealthReportsLiveLatencyJitterAndLoss(t *testing.T) {
	memory := newMemoryCarrier()
	memory.probeLatency = []time.Duration{10 * time.Millisecond, 14 * time.Millisecond, 18 * time.Millisecond, 22 * time.Millisecond}
	backend := connectedBackend(t, memory)
	health, err := backend.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !health.Reachable || health.LatencyMS != 16 || health.JitterMS != 4 || health.LossPercent != 0 || memory.probeCalls != healthProbeCount {
		t.Fatalf("unexpected live health sample: %#v calls=%d", health, memory.probeCalls)
	}
}

func TestBackendHealthDetectsPostConnectCarrierFailure(t *testing.T) {
	memory := newMemoryCarrier()
	memory.probeFailures = []error{net.ErrClosed}
	backend := connectedBackend(t, memory)
	health, err := backend.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Reachable || health.LatencyMS != 0 || health.JitterMS != 0 || health.LossPercent != 100 || memory.probeCalls != 1 {
		t.Fatalf("carrier failure was not reflected in bounded health facts: %#v calls=%d", health, memory.probeCalls)
	}
}

func TestBackendHealthReportsPartialLossMetrics(t *testing.T) {
	for _, test := range []struct {
		name        string
		failureAt   int
		wantLoss    uint8
		wantLatency uint32
		wantJitter  uint32
	}{
		{name: "seventy-five percent", failureAt: 1, wantLoss: 75, wantLatency: 10},
		{name: "fifty percent", failureAt: 2, wantLoss: 50, wantLatency: 15, wantJitter: 10},
		{name: "twenty-five percent", failureAt: 3, wantLoss: 25, wantLatency: 20, wantJitter: 10},
	} {
		t.Run(test.name, func(t *testing.T) {
			memory := newMemoryCarrier()
			memory.probeLatency = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond, 40 * time.Millisecond}
			memory.probeFailures = make([]error, healthProbeCount)
			memory.probeFailures[test.failureAt] = net.ErrClosed
			backend := connectedBackend(t, memory)
			health, err := backend.Health(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if health.Reachable || health.LossPercent != test.wantLoss || health.LatencyMS != test.wantLatency || health.JitterMS != test.wantJitter {
				t.Fatalf("unexpected partial-loss metrics: %#v", health)
			}
			if memory.probeCalls != test.failureAt+1 {
				t.Fatalf("probe continued after ambiguous loss: calls=%d", memory.probeCalls)
			}
		})
	}
}

func TestCarrierHealthReportsActualKYNPControlFrameLoss(t *testing.T) {
	for _, test := range []struct {
		dropAt   int
		wantLoss uint8
	}{
		{dropAt: 2, wantLoss: 75},
		{dropAt: 3, wantLoss: 50},
		{dropAt: 4, wantLoss: 25},
	} {
		t.Run(fmt.Sprintf("drop-pong-%d", test.dropAt), func(t *testing.T) {
			clientConnection, serverConnection := net.Pipe()
			client := carrier.NewStream(clientConnection)
			dropper := &dropPongConnection{Conn: serverConnection, dropAt: test.dropAt}
			server := carrier.NewStream(dropper)
			board := wgcarrier.NewSwitchboard()
			if err := board.Attach(client); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			defer board.Shutdown()
			defer server.Close()
			go func() { _, _ = client.Receive(ctx) }()
			go func() { _, _ = server.Receive(ctx) }()

			health, err := sampleCarrierHealth(ctx, board)
			if err != nil {
				t.Fatal(err)
			}
			if health.Reachable || health.LossPercent != test.wantLoss {
				t.Fatalf("unexpected KYNP control-frame loss metrics: %#v", health)
			}
			dropper.mu.Lock()
			pongSeen := dropper.pongSeen
			dropper.mu.Unlock()
			if pongSeen != test.dropAt {
				t.Fatalf("unexpected pong count before fail-closed stop: %d", pongSeen)
			}
		})
	}
}

func TestBackendHealthParentCancellationIsBoundedAndReleasesOperation(t *testing.T) {
	packetCarrier := &blockingProbeCarrier{memoryCarrier: newMemoryCarrier(), started: make(chan struct{})}
	backend := connectedBackend(t, packetCarrier)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := backend.Health(ctx)
		result <- err
	}()
	select {
	case <-packetCarrier.started:
	case <-time.After(time.Second):
		t.Fatal("health probe did not start")
	}
	started := time.Now()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("parent cancellation did not reach health probe: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not bound health probe")
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("health parent cancellation exceeded bound: %v", elapsed)
	}
	operationActive := backend.operationCancel.Load() != nil
	if operationActive {
		t.Fatal("health cancellation retained operation state")
	}
	if err := backend.Disconnect(context.Background()); err != nil {
		t.Fatalf("disconnect failed after cancelled health: %v", err)
	}
}

func TestBackendHealthContextCancelInterruptsAndAllowsDisconnect(t *testing.T) {
	packetCarrier := &blockingProbeCarrier{memoryCarrier: newMemoryCarrier(), started: make(chan struct{})}
	backend := connectedBackend(t, packetCarrier)
	healthContext, cancelHealth := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := backend.Health(healthContext)
		result <- err
	}()
	select {
	case <-packetCarrier.started:
	case <-time.After(time.Second):
		t.Fatal("health probe did not start")
	}
	cancelHealth()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("health context cancel did not reach operation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("health context cancel did not bound operation")
	}
	if err := backend.Disconnect(context.Background()); err != nil {
		t.Fatalf("disconnect failed after backend health cancel: %v", err)
	}
}

func TestBackendHealthReturnsProbeUnavailableWithoutFabricatedMetrics(t *testing.T) {
	backend := connectedBackend(t, &packetOnlyCarrier{inner: newMemoryCarrier()})
	health, err := backend.Health(context.Background())
	if !errors.Is(err, carrier.ErrProbeUnavailable) {
		t.Fatalf("expected probe-unavailable failure, got health=%#v err=%v", health, err)
	}
	if health != (ipc.Health{}) {
		t.Fatalf("probe-unavailable path fabricated metrics: %#v", health)
	}
}

func TestSummarizeLatencySaturatesWireFacts(t *testing.T) {
	latency, jitter := summarizeLatency([]time.Duration{0, time.Duration(uint64(^uint32(0))+10) * time.Millisecond})
	if latency == 0 || jitter != ^uint32(0) {
		t.Fatalf("unexpected bounded summary: latency=%d jitter=%d", latency, jitter)
	}
}
