package frame

import (
	"errors"
	"testing"
	"time"
)

func TestFragmentRoundTripAndOutOfOrderReassembly(t *testing.T) {
	parts := []Frame{
		{Kind: KindWireGuardPacket, Sequence: 2, Fragment: &Fragment{MessageID: 7, Index: 1, Count: 3}, Payload: []byte("b")},
		{Kind: KindWireGuardPacket, Sequence: 1, Fragment: &Fragment{MessageID: 7, Index: 0, Count: 3}, Payload: []byte("a")},
		{Kind: KindWireGuardPacket, Sequence: 3, Fragment: &Fragment{MessageID: 7, Index: 2, Count: 3}, Payload: []byte("c")},
	}
	reassembler := NewReassembler(time.Second)
	for index, part := range parts {
		encoded, err := Encode(part)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeDatagram(encoded)
		if err != nil {
			t.Fatal(err)
		}
		packet, complete, err := reassembler.Accept(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if index < 2 && complete {
			t.Fatal("assembly completed early")
		}
		if index == 2 && (!complete || string(packet) != "abc") {
			t.Fatalf("unexpected assembly: complete=%v packet=%q", complete, packet)
		}
	}
}

func TestFragmentValidationFailsClosed(t *testing.T) {
	for _, fragment := range []*Fragment{
		{Count: 1},
		{Index: 2, Count: 2},
		{Count: MaxFragments + 1},
	} {
		frame := Frame{Kind: KindWireGuardPacket, Fragment: fragment, Payload: []byte{1}}
		if _, err := Encode(frame); !errors.Is(err, ErrInvalidFragment) {
			t.Fatalf("expected invalid fragment for %#v, got %v", fragment, err)
		}
	}
}

func TestReassemblyRejectsDuplicateInconsistentAndCompletedReplay(t *testing.T) {
	first := Frame{Kind: KindWireGuardPacket, Fragment: &Fragment{MessageID: 8, Count: 2}, Payload: []byte{1}}
	reassembler := NewReassembler(time.Second)
	if _, _, err := reassembler.Accept(first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reassembler.Accept(first); !errors.Is(err, ErrDuplicateFragment) {
		t.Fatalf("expected duplicate refusal, got %v", err)
	}
	inconsistent := Frame{Kind: KindWireGuardPacket, Fragment: &Fragment{MessageID: 8, Index: 1, Count: 3}, Payload: []byte{2}}
	if _, _, err := reassembler.Accept(inconsistent); !errors.Is(err, ErrInvalidFragment) {
		t.Fatalf("expected inconsistent count refusal, got %v", err)
	}
	second := Frame{Kind: KindWireGuardPacket, Fragment: &Fragment{MessageID: 8, Index: 1, Count: 2}, Payload: []byte{2}}
	if _, complete, err := reassembler.Accept(second); err != nil || !complete {
		t.Fatalf("expected completion, complete=%v err=%v", complete, err)
	}
	if _, _, err := reassembler.Accept(first); !errors.Is(err, ErrDuplicateFragment) {
		t.Fatalf("expected completed replay refusal, got %v", err)
	}
}

func TestReassemblyExpiryAndConcurrentBound(t *testing.T) {
	now := time.Unix(100, 0)
	reassembler := NewReassembler(time.Second)
	reassembler.now = func() time.Time { return now }
	for messageID := range uint64(defaultMaxAssemblies) {
		part := Frame{Kind: KindWireGuardPacket, Fragment: &Fragment{MessageID: messageID, Count: 2}, Payload: []byte{1}}
		if _, _, err := reassembler.Accept(part); err != nil {
			t.Fatal(err)
		}
	}
	overflow := Frame{Kind: KindWireGuardPacket, Fragment: &Fragment{MessageID: 99, Count: 2}, Payload: []byte{1}}
	if _, _, err := reassembler.Accept(overflow); !errors.Is(err, ErrAssemblyLimit) {
		t.Fatalf("expected assembly bound, got %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, _, err := reassembler.Accept(overflow); err != nil {
		t.Fatalf("expired assemblies were not cleared: %v", err)
	}
}

func TestReassemblyTotalSizeBound(t *testing.T) {
	reassembler := NewReassembler(time.Second)
	first := Frame{Kind: KindWireGuardPacket, Fragment: &Fragment{MessageID: 1, Count: 2}, Payload: make([]byte, MaxPayloadSize)}
	if _, _, err := reassembler.Accept(first); err != nil {
		t.Fatal(err)
	}
	second := Frame{Kind: KindWireGuardPacket, Fragment: &Fragment{MessageID: 1, Index: 1, Count: 2}, Payload: []byte{1}}
	if _, _, err := reassembler.Accept(second); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected total size bound, got %v", err)
	}
}
