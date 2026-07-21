package wgcarrier

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestSwitchboardRequiresExplicitBreakBeforeMake(t *testing.T) {
	board := NewSwitchboard()
	first, firstPeer := newCarrierPair()
	second, _ := newCarrierPair()
	if err := board.Attach(first); err != nil {
		t.Fatal(err)
	}
	if err := board.Attach(second); !errors.Is(err, ErrCarrierAttached) {
		t.Fatalf("expected make-before-break refusal, got %v", err)
	}
	firstPeer.incoming <- []byte("packet")
	if err := board.Send(context.Background(), []byte("packet")); err != nil {
		t.Fatal(err)
	}
	if err := board.Detach(); err != nil {
		t.Fatal(err)
	}
	if err := board.Attach(second); err != nil {
		t.Fatal(err)
	}
	if err := board.Close(); err != nil {
		t.Fatal(err)
	}
	if err := board.Attach(first); err != nil {
		t.Fatal(err)
	}
	if err := board.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if err := board.Attach(first); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected closed refusal, got %v", err)
	}
}
