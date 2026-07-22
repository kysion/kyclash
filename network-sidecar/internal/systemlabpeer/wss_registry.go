package systemlabpeer

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
)

// wssRegistry owns every connection after websocket.Accept hijacks it from
// net/http. http.Server.Close deliberately does not close hijacked
// connections, so the system-lab peer must retain and drain them explicitly.
type wssRegistry struct {
	mu      sync.Mutex
	changed *sync.Cond
	closing bool
	closed  chan struct{}
	entries map[*registeredWSSCarrier]struct{}
	active  int
	total   int
}

func newWSSRegistry() *wssRegistry {
	registry := &wssRegistry{
		closed:  make(chan struct{}),
		entries: make(map[*registeredWSSCarrier]struct{}),
	}
	registry.changed = sync.NewCond(&registry.mu)
	return registry
}

func (registry *wssRegistry) register(value carrier.Carrier, force func() error) (*registeredWSSCarrier, error) {
	if value == nil {
		return nil, ErrInvalidConfig
	}
	registered := &registeredWSSCarrier{Carrier: value, registry: registry, force: force}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closing {
		return nil, net.ErrClosed
	}
	registry.entries[registered] = struct{}{}
	registry.total++
	return registered, nil
}

func (registry *wssRegistry) unregister(value *registeredWSSCarrier) {
	registry.mu.Lock()
	if _, present := registry.entries[value]; present {
		delete(registry.entries, value)
		registry.changed.Broadcast()
	}
	registry.mu.Unlock()
}

func (registry *wssRegistry) beginHandler() bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closing {
		return false
	}
	registry.active++
	return true
}

func (registry *wssRegistry) endHandler() {
	registry.mu.Lock()
	registry.active--
	registry.changed.Broadcast()
	registry.mu.Unlock()
}

func (registry *wssRegistry) stopping() <-chan struct{} { return registry.closed }

func (registry *wssRegistry) closeAndWait() {
	registry.mu.Lock()
	if !registry.closing {
		registry.closing = true
		close(registry.closed)
	}
	connections := make([]*registeredWSSCarrier, 0, len(registry.entries))
	for connection := range registry.entries {
		connections = append(connections, connection)
	}
	registry.mu.Unlock()

	for _, connection := range connections {
		_ = connection.Close()
	}

	registry.mu.Lock()
	for len(registry.entries) != 0 || registry.active != 0 {
		registry.changed.Wait()
	}
	registry.mu.Unlock()
}

func (registry *wssRegistry) counts() (connections, handlers, registrations int) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return len(registry.entries), registry.active, registry.total
}

type registeredWSSCarrier struct {
	carrier.Carrier
	registry *wssRegistry
	force    func() error
	once     sync.Once
	err      error
}

func (registered *registeredWSSCarrier) Close() error {
	registered.once.Do(func() {
		if registered.force != nil {
			_ = registered.force()
		}
		registered.err = registered.Carrier.Close()
		registered.registry.unregister(registered)
	})
	return registered.err
}

func (registered *registeredWSSCarrier) Probe(ctx context.Context) (time.Duration, error) {
	prober, ok := registered.Carrier.(carrier.Prober)
	if !ok {
		return 0, carrier.ErrProbeUnavailable
	}
	return prober.Probe(ctx)
}

var _ carrier.Carrier = (*registeredWSSCarrier)(nil)
var _ carrier.Prober = (*registeredWSSCarrier)(nil)
