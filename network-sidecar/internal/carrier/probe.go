package carrier

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrProbeUnavailable = errors.New("carrier health probe unavailable")
	ErrProbeFailed      = errors.New("carrier health probe failed")
)

const probeCancellationDrainTimeout = 250 * time.Millisecond

// Prober measures one live KYNP ping/pong round trip on an already-connected
// carrier. The control frames share the carrier sequence space with encrypted
// WireGuard packets and never carry a payload.
type Prober interface {
	Probe(context.Context) (time.Duration, error)
}

// probeState serializes the payload-free KYNP ping/pong exchange. Because v1
// deliberately has no correlation payload, a timed-out exchange makes the
// probe state terminal for this connection: a late pong can then never be
// mistaken for a later sample. Rust remains responsible for disconnecting the
// failed carrier and explicitly selecting any fallback.
type probeState struct {
	serial chan struct{}
	state  sync.Mutex
	failed bool
	pongs  chan struct{}
}

func newProbeState() probeState {
	serial := make(chan struct{}, 1)
	serial <- struct{}{}
	return probeState{serial: serial, pongs: make(chan struct{}, 1)}
}

func (state *probeState) measure(ctx context.Context, closed <-chan struct{}, send func(context.Context) (bool, error)) (time.Duration, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-closed:
		return 0, ErrClosed
	case <-state.serial:
	}
	defer func() { state.serial <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	state.state.Lock()
	failed := state.failed
	state.state.Unlock()
	if failed {
		return 0, ErrProbeFailed
	}
	select {
	case <-closed:
		return 0, ErrClosed
	default:
	}
	for {
		select {
		case <-state.pongs:
			continue
		default:
		}
		break
	}
	started := time.Now()
	dispatched, err := send(ctx)
	if err != nil {
		if !dispatched {
			return 0, err
		}
		if cancelErr := ctx.Err(); cancelErr != nil {
			return 0, state.drainCancelledPong(cancelErr, closed)
		}
		state.fail()
		return 0, err
	}
	if !dispatched {
		state.fail()
		return 0, ErrProbeFailed
	}
	if cancelErr := ctx.Err(); cancelErr != nil {
		return 0, state.drainCancelledPong(cancelErr, closed)
	}
	select {
	case <-state.pongs:
		// Cancellation may become observable after the select chose an
		// already-buffered Pong. Preserve the caller's cancellation result;
		// the matching Pong has been consumed, so the carrier remains safe to
		// reuse without another drain.
		if cancelErr := ctx.Err(); cancelErr != nil {
			return 0, cancelErr
		}
		return time.Since(started), nil
	case <-closed:
		state.fail()
		return 0, ErrClosed
	case <-ctx.Done():
		return 0, state.drainCancelledPong(ctx.Err(), closed)
	}
}

func (state *probeState) drainCancelledPong(cancelErr error, closed <-chan struct{}) error {
	// Ping and Pong deliberately carry no correlation payload in KYNP v1.
	// The caller still holds the serialization gate while this independently
	// bounded drain waits for the response to the already-dispatched Ping. A
	// responsive peer therefore leaves the carrier reusable after cancellation,
	// while an unresolved response is terminal so it can never be mistaken for a
	// later probe's Pong.
	timer := time.NewTimer(probeCancellationDrainTimeout)
	defer timer.Stop()
	select {
	case <-state.pongs:
		return cancelErr
	case <-closed:
		state.fail()
		return ErrClosed
	case <-timer.C:
		state.fail()
		return cancelErr
	}
}

func (state *probeState) observePong() {
	state.state.Lock()
	failed := state.failed
	state.state.Unlock()
	if failed {
		return
	}
	select {
	case state.pongs <- struct{}{}:
	default:
	}
}

func (state *probeState) fail() {
	state.state.Lock()
	state.failed = true
	state.state.Unlock()
}
