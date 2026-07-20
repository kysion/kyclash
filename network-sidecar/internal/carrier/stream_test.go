package carrier

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/frame"
)

func TestStreamRoundTripAndCloseIdempotence(t *testing.T) {
	leftConnection, rightConnection := net.Pipe()
	left := NewStream(leftConnection)
	right := NewStream(rightConnection)
	packet := []byte("encrypted-wireguard-packet")
	sent := make(chan error, 1)
	go func() { sent <- left.Send(context.Background(), packet) }()
	received, err := right.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, packet) {
		t.Fatalf("packet mismatch: %q", received)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
	if err := left.Send(context.Background(), packet); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected closed refusal, got %v", err)
	}
	_ = right.Close()
}

func TestReceiveCancellationUnblocksAndConnectionRemainsUsable(t *testing.T) {
	leftConnection, rightConnection := net.Pipe()
	left := NewStream(leftConnection)
	right := NewStream(rightConnection)
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := right.Receive(ctx)
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("receive did not unblock")
	}
	sent := make(chan error, 1)
	go func() { sent <- left.Send(context.Background(), []byte{9}) }()
	packet, err := right.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, []byte{9}) {
		t.Fatalf("unexpected packet: %v", packet)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

func TestReceiveRejectsReplayAndControlFrames(t *testing.T) {
	for _, test := range []struct {
		name   string
		frames []frame.Frame
		want   error
	}{
		{"replay", []frame.Frame{{Kind: frame.KindWireGuardPacket, Sequence: 2}, {Kind: frame.KindWireGuardPacket, Sequence: 2}}, frame.ErrNonMonotonic},
		{"control", []frame.Frame{{Kind: frame.KindPing, Sequence: 1}}, ErrUnexpectedFrame},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer, reader := net.Pipe()
			stream := NewStream(reader)
			defer stream.Close()
			go func() {
				defer writer.Close()
				for _, item := range test.frames {
					encoded, err := frame.Encode(item)
					if err != nil {
						return
					}
					_ = writeFull(writer, encoded)
				}
			}()
			var got error
			for range test.frames {
				_, got = stream.Receive(context.Background())
			}
			if !errors.Is(got, test.want) {
				t.Fatalf("expected %v, got %v", test.want, got)
			}
		})
	}
}

func TestSendRejectsOversizedPacket(t *testing.T) {
	leftConnection, rightConnection := net.Pipe()
	stream := NewStream(leftConnection)
	defer stream.Close()
	defer rightConnection.Close()
	err := stream.Send(context.Background(), make([]byte, frame.MaxPayloadSize+1))
	if !errors.Is(err, frame.ErrPayloadTooLarge) {
		t.Fatalf("expected payload bound, got %v", err)
	}
}
