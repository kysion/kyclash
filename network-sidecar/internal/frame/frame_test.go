package frame

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestRoundTripWireGuardPacket(t *testing.T) {
	original := Frame{Kind: KindWireGuardPacket, Sequence: 42, Payload: []byte{1, 2, 3}}
	encoded, err := Encode(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDatagram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != original.Kind || decoded.Sequence != original.Sequence || !bytes.Equal(decoded.Payload, original.Payload) {
		t.Fatalf("round trip mismatch: %#v", decoded)
	}
}

func TestControlFramesRequireEmptyPayload(t *testing.T) {
	_, err := Encode(Frame{Kind: KindPing, Payload: []byte{1}})
	if !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("expected invalid kind, got %v", err)
	}
}

func TestDecodeFailsClosed(t *testing.T) {
	valid, err := Encode(Frame{Kind: KindWireGuardPacket, Sequence: 1, Payload: []byte{7}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func([]byte) []byte
		want error
	}{
		{"magic", func(data []byte) []byte { data[0] = 0; return data }, ErrInvalidMagic},
		{"version", func(data []byte) []byte { data[4]++; return data }, ErrUnsupportedVersion},
		{"kind", func(data []byte) []byte { data[5] = 99; return data }, ErrInvalidKind},
		{"flags", func(data []byte) []byte { data[7] = 2; return data }, ErrUnknownFlags},
		{"oversize", func(data []byte) []byte { data[8], data[9], data[10], data[11] = 0, 1, 0, 0; return data }, ErrPayloadTooLarge},
		{"trailing", func(data []byte) []byte { return append(data, 0) }, ErrTrailingData},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := test.edit(bytes.Clone(valid))
			_, got := DecodeDatagram(input)
			if !errors.Is(got, test.want) {
				t.Fatalf("expected %v, got %v", test.want, got)
			}
		})
	}
}

func TestTruncatedFrameFails(t *testing.T) {
	valid, err := Encode(Frame{Kind: KindWireGuardPacket, Payload: []byte{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	for length := range len(valid) {
		_, got := DecodeDatagram(valid[:length])
		if !errors.Is(got, io.ErrUnexpectedEOF) && !errors.Is(got, io.EOF) {
			t.Fatalf("length %d: expected truncation error, got %v", length, got)
		}
	}
}

func TestMaximumPayloadAndOversizeRefusal(t *testing.T) {
	maximum := Frame{Kind: KindWireGuardPacket, Payload: make([]byte, MaxPayloadSize)}
	if _, err := Encode(maximum); err != nil {
		t.Fatal(err)
	}
	maximum.Payload = append(maximum.Payload, 0)
	if _, err := Encode(maximum); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected payload bound, got %v", err)
	}
}

func TestSequenceValidator(t *testing.T) {
	var validator SequenceValidator
	for _, sequence := range []uint64{0, 1, 9} {
		if err := validator.Accept(sequence); err != nil {
			t.Fatal(err)
		}
	}
	for _, sequence := range []uint64{9, 8} {
		if err := validator.Accept(sequence); !errors.Is(err, ErrNonMonotonic) {
			t.Fatalf("expected non-monotonic refusal, got %v", err)
		}
	}
}

func FuzzDecodeDatagram(fuzzer *testing.F) {
	seed, err := Encode(Frame{Kind: KindWireGuardPacket, Sequence: 1, Payload: []byte("packet")})
	if err != nil {
		fuzzer.Fatal(err)
	}
	fuzzer.Add(seed)
	fuzzer.Fuzz(func(t *testing.T, input []byte) {
		decoded, err := DecodeDatagram(input)
		if err != nil {
			return
		}
		encoded, err := Encode(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, input) {
			t.Fatal("accepted datagram was not canonical")
		}
	})
}
