package wgcarrier

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
)

var (
	ErrCarrierAttached = errors.New("packet carrier already attached")
	ErrNoCarrier       = errors.New("no packet carrier attached")
)

// Switchboard keeps one WireGuard Bind stable while Rust explicitly selects
// and replaces carriers. It never chooses a carrier or performs fallback.
type Switchboard struct {
	mu     sync.RWMutex
	active carrier.Carrier
	closed bool
}

func NewSwitchboard() *Switchboard {
	return &Switchboard{}
}

func (board *Switchboard) Attach(next carrier.Carrier) error {
	if next == nil {
		return ErrNoCarrier
	}
	board.mu.Lock()
	defer board.mu.Unlock()
	if board.closed {
		return net.ErrClosed
	}
	if board.active != nil {
		return ErrCarrierAttached
	}
	board.active = next
	return nil
}

func (board *Switchboard) Detach() error {
	board.mu.Lock()
	active := board.active
	board.active = nil
	closed := board.closed
	board.mu.Unlock()
	if active == nil {
		if closed {
			return net.ErrClosed
		}
		return ErrNoCarrier
	}
	return active.Close()
}

func (board *Switchboard) Send(ctx context.Context, packet []byte) error {
	active, err := board.current()
	if err != nil {
		return err
	}
	return active.Send(ctx, packet)
}

func (board *Switchboard) Receive(ctx context.Context) ([]byte, error) {
	active, err := board.current()
	if err != nil {
		return nil, err
	}
	return active.Receive(ctx)
}

func (board *Switchboard) Probe(ctx context.Context) (time.Duration, error) {
	active, err := board.current()
	if err != nil {
		return 0, err
	}
	prober, ok := active.(carrier.Prober)
	if !ok {
		return 0, carrier.ErrProbeUnavailable
	}
	return prober.Probe(ctx)
}

func (board *Switchboard) Close() error {
	err := board.Detach()
	if errors.Is(err, ErrNoCarrier) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (board *Switchboard) Shutdown() error {
	board.mu.Lock()
	if board.closed {
		board.mu.Unlock()
		return nil
	}
	board.closed = true
	active := board.active
	board.active = nil
	board.mu.Unlock()
	if active != nil {
		return active.Close()
	}
	return nil
}

func (board *Switchboard) current() (carrier.Carrier, error) {
	board.mu.RLock()
	defer board.mu.RUnlock()
	if board.closed {
		return nil, net.ErrClosed
	}
	if board.active == nil {
		return nil, ErrNoCarrier
	}
	return board.active, nil
}

var _ carrier.Carrier = (*Switchboard)(nil)
var _ carrier.Prober = (*Switchboard)(nil)
