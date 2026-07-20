package wgcarrier

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

type memoryCarrier struct {
	incoming  chan []byte
	outgoing  chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newMemoryCarrier() *memoryCarrier {
	return &memoryCarrier{
		incoming: make(chan []byte, 1),
		outgoing: make(chan []byte, 1),
		closed:   make(chan struct{}),
	}
}

func (memory *memoryCarrier) Send(ctx context.Context, packet []byte) error {
	select {
	case memory.outgoing <- append([]byte(nil), packet...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-memory.closed:
		return net.ErrClosed
	}
}

func (memory *memoryCarrier) Receive(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-memory.incoming:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-memory.closed:
		return nil, net.ErrClosed
	}
}

func (memory *memoryCarrier) Close() error {
	memory.closeOnce.Do(func() { close(memory.closed) })
	return nil
}

func TestBindReceivesAndSendsPackets(t *testing.T) {
	memory := newMemoryCarrier()
	bind, err := NewBind(memory, "site-1")
	if err != nil {
		t.Fatal(err)
	}
	receivers, port, err := bind.Open(1234)
	if err != nil {
		t.Fatal(err)
	}
	if port != 0 || len(receivers) != 1 || bind.BatchSize() != 1 {
		t.Fatalf("unexpected bind contract: port=%d receivers=%d batch=%d", port, len(receivers), bind.BatchSize())
	}
	memory.incoming <- []byte{1, 2, 3}
	packets := [][]byte{make([]byte, 16)}
	sizes := make([]int, 1)
	endpoints := make([]conn.Endpoint, 1)
	count, err := receivers[0](packets, sizes, endpoints)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || sizes[0] != 3 || endpoints[0].DstToString() != "site-1" {
		t.Fatalf("unexpected receive result: count=%d size=%d endpoint=%v", count, sizes[0], endpoints[0])
	}
	if err := bind.Send([][]byte{{4, 5}}, endpoints[0]); err != nil {
		t.Fatal(err)
	}
	if packet := <-memory.outgoing; len(packet) != 2 || packet[0] != 4 {
		t.Fatalf("unexpected sent packet: %v", packet)
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBindCloseUnblocksReceive(t *testing.T) {
	memory := newMemoryCarrier()
	bind, err := NewBind(memory, "site-1")
	if err != nil {
		t.Fatal(err)
	}
	receivers, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, receiveErr := receivers[0]([][]byte{make([]byte, 16)}, make([]int, 1), make([]conn.Endpoint, 1))
		result <- receiveErr
	}()
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected closed receive, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("receive did not unblock")
	}
}

func TestBindFailsClosedOnEndpointAndBufferErrors(t *testing.T) {
	memory := newMemoryCarrier()
	bind, err := NewBind(memory, "site-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bind.ParseEndpoint("site-2"); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("expected endpoint refusal, got %v", err)
	}
	endpoint, err := bind.ParseEndpoint("site-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{{1}}, endpoint); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected send-before-open refusal, got %v", err)
	}
	receivers, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("expected already-open refusal, got %v", err)
	}
	memory.incoming <- []byte{1, 2}
	_, err = receivers[0]([][]byte{make([]byte, 1)}, make([]int, 1), make([]conn.Endpoint, 1))
	if !errors.Is(err, ErrPacketBuffer) {
		t.Fatalf("expected buffer refusal, got %v", err)
	}
	_ = bind.Close()
}
