package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchParentSkipsInitOwnedProcess(t *testing.T) {
	called := atomic.Bool{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		watchParentWith(ctx, 1, func() {}, func() int {
			called.Store(true)
			return 1
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("init-owned parent watcher did not return")
	}
	if called.Load() {
		t.Fatal("init-owned watcher sampled a parent")
	}
}

func TestWatchParentCancelsAfterReparenting(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	var samples atomic.Int32
	cancelled := make(chan struct{})
	go watchParentWith(ctx, 42, func() { close(cancelled) }, func() int {
		if samples.Add(1) == 1 {
			return 42
		}
		return 1
	})
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("parent watcher did not cancel after reparenting")
	}
}

func TestWatchParentStopsWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchParentWith(ctx, 42, func() { t.Error("unexpected parent cancellation") }, func() int { return 42 })
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("parent watcher did not observe context cancellation")
	}
}
