package userspace

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

type memoryCarrier struct {
	closed chan struct{}
	once   sync.Once
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
		if backend.active != "" || backend.operationCancel != nil {
			t.Fatalf("cycle %d left carrier state attached: active=%q cancel=%v", cycle, backend.active, backend.operationCancel != nil)
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
	go func() { result <- backend.Connect(context.Background(), profile.QUIC, endpoint) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	if err := backend.Cancel("operation.test"); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) || backend.active != "" {
		t.Fatalf("cancel did not preserve disconnected carrier state: %v", err)
	}
	_ = backend.Close()
}
