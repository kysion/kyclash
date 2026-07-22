package carrier

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProbeSerializationWaitHonorsContext(t *testing.T) {
	state := newProbeState()
	closed := make(chan struct{})
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := state.measure(context.Background(), closed, func(context.Context) (bool, error) {
			close(started)
			<-release
			return true, ErrProbeFailed
		})
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first probe did not acquire serialization gate")
	}

	waitContext, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	startedWaiting := time.Now()
	if _, err := state.measure(waitContext, closed, func(context.Context) (bool, error) {
		t.Fatal("cancelled waiter unexpectedly sent a probe")
		return false, nil
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("serialized probe wait ignored context: %v", err)
	}
	if elapsed := time.Since(startedWaiting); elapsed > 250*time.Millisecond {
		t.Fatalf("serialized probe cancellation exceeded bound: %v", elapsed)
	}
	close(release)
	select {
	case err := <-firstDone:
		if !errors.Is(err, ErrProbeFailed) {
			t.Fatalf("unexpected first probe result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first probe did not release serialization gate")
	}
}

func TestProbeCancellationBeforeDispatchDoesNotPoisonState(t *testing.T) {
	state := newProbeState()
	closed := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := state.measure(ctx, closed, func(context.Context) (bool, error) {
		cancel()
		return false, context.Canceled
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-dispatch cancellation returned %v", err)
	}
	if _, err := state.measure(context.Background(), closed, func(context.Context) (bool, error) {
		state.observePong()
		return true, nil
	}); err != nil {
		t.Fatalf("pre-dispatch cancellation poisoned later probe: %v", err)
	}
}

func TestProbeCancellationDuringDispatchDrainsBeforeReuse(t *testing.T) {
	state := newProbeState()
	closed := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := state.measure(ctx, closed, func(context.Context) (bool, error) {
		cancel()
		go func() {
			time.Sleep(10 * time.Millisecond)
			state.observePong()
		}()
		return true, context.Canceled
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("in-dispatch cancellation returned %v", err)
	}
	if _, err := state.measure(context.Background(), closed, func(context.Context) (bool, error) {
		state.observePong()
		return true, nil
	}); err != nil {
		t.Fatalf("drained in-dispatch cancellation poisoned later probe: %v", err)
	}
}
