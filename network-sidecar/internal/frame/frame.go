// Package frame implements the transport-independent KyClash network packet
// envelope. It performs no network, tunnel, route, DNS, or credential I/O.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Version            = uint8(1)
	HeaderSize         = 20
	FragmentHeaderSize = 12
	MaxPayloadSize     = 65_535
	MaxFragments       = 64
)

const flagFragmented = uint16(1)

var magic = [4]byte{'K', 'Y', 'N', 'P'}

var (
	ErrInvalidMagic       = errors.New("invalid frame magic")
	ErrUnsupportedVersion = errors.New("unsupported frame version")
	ErrInvalidKind        = errors.New("invalid frame kind")
	ErrUnknownFlags       = errors.New("unknown frame flags")
	ErrPayloadTooLarge    = errors.New("frame payload too large")
	ErrTrailingData       = errors.New("trailing data after datagram frame")
	ErrNonMonotonic       = errors.New("non-monotonic frame sequence")
	ErrInvalidFragment    = errors.New("invalid frame fragment")
	ErrDuplicateFragment  = errors.New("duplicate frame fragment")
	ErrAssemblyLimit      = errors.New("fragment assembly limit exceeded")
	ErrAssemblyExpired    = errors.New("fragment assembly expired")
)

type Kind uint8

const (
	KindWireGuardPacket Kind = 1
	KindPing            Kind = 2
	KindPong            Kind = 3
	KindClose           Kind = 4
)

func (kind Kind) valid() bool {
	return kind >= KindWireGuardPacket && kind <= KindClose
}

type Frame struct {
	Kind     Kind
	Sequence uint64
	Fragment *Fragment
	Payload  []byte
}

type Fragment struct {
	MessageID uint64
	Index     uint16
	Count     uint16
}

func (frame Frame) Validate() error {
	if !frame.Kind.valid() {
		return ErrInvalidKind
	}
	if len(frame.Payload) > MaxPayloadSize {
		return ErrPayloadTooLarge
	}
	if frame.Fragment != nil {
		if frame.Kind != KindWireGuardPacket || frame.Fragment.Count < 2 || frame.Fragment.Count > MaxFragments || frame.Fragment.Index >= frame.Fragment.Count || len(frame.Payload) == 0 {
			return ErrInvalidFragment
		}
		return nil
	}
	if frame.Kind != KindWireGuardPacket && len(frame.Payload) != 0 {
		return fmt.Errorf("control frame payload: %w", ErrInvalidKind)
	}
	return nil
}

func Encode(frame Frame) ([]byte, error) {
	if err := frame.Validate(); err != nil {
		return nil, err
	}
	extraHeader := 0
	if frame.Fragment != nil {
		extraHeader = FragmentHeaderSize
	}
	encoded := make([]byte, HeaderSize+extraHeader+len(frame.Payload))
	copy(encoded[:4], magic[:])
	encoded[4] = Version
	encoded[5] = byte(frame.Kind)
	if frame.Fragment != nil {
		binary.BigEndian.PutUint16(encoded[6:8], flagFragmented)
		binary.BigEndian.PutUint64(encoded[20:28], frame.Fragment.MessageID)
		binary.BigEndian.PutUint16(encoded[28:30], frame.Fragment.Index)
		binary.BigEndian.PutUint16(encoded[30:32], frame.Fragment.Count)
	}
	binary.BigEndian.PutUint32(encoded[8:12], uint32(len(frame.Payload)))
	binary.BigEndian.PutUint64(encoded[12:20], frame.Sequence)
	copy(encoded[HeaderSize+extraHeader:], frame.Payload)
	return encoded, nil
}

func Decode(reader io.Reader) (Frame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return Frame{}, fmt.Errorf("read frame header: %w", err)
	}
	if [4]byte(header[:4]) != magic {
		return Frame{}, ErrInvalidMagic
	}
	if header[4] != Version {
		return Frame{}, ErrUnsupportedVersion
	}
	kind := Kind(header[5])
	if !kind.valid() {
		return Frame{}, ErrInvalidKind
	}
	flags := binary.BigEndian.Uint16(header[6:8])
	if flags & ^flagFragmented != 0 {
		return Frame{}, ErrUnknownFlags
	}
	payloadLength := binary.BigEndian.Uint32(header[8:12])
	if payloadLength > MaxPayloadSize {
		return Frame{}, ErrPayloadTooLarge
	}
	decoded := Frame{
		Kind:     kind,
		Sequence: binary.BigEndian.Uint64(header[12:20]),
		Payload:  make([]byte, int(payloadLength)),
	}
	if flags&flagFragmented != 0 {
		fragmentHeader := make([]byte, FragmentHeaderSize)
		if _, err := io.ReadFull(reader, fragmentHeader); err != nil {
			return Frame{}, fmt.Errorf("read fragment header: %w", err)
		}
		decoded.Fragment = &Fragment{
			MessageID: binary.BigEndian.Uint64(fragmentHeader[:8]),
			Index:     binary.BigEndian.Uint16(fragmentHeader[8:10]),
			Count:     binary.BigEndian.Uint16(fragmentHeader[10:12]),
		}
	}
	if _, err := io.ReadFull(reader, decoded.Payload); err != nil {
		return Frame{}, fmt.Errorf("read frame payload: %w", err)
	}
	if err := decoded.Validate(); err != nil {
		return Frame{}, err
	}
	return decoded, nil
}

func DecodeDatagram(datagram []byte) (Frame, error) {
	reader := &boundedReader{data: datagram}
	decoded, err := Decode(reader)
	if err != nil {
		return Frame{}, err
	}
	if len(reader.data) != 0 {
		return Frame{}, ErrTrailingData
	}
	return decoded, nil
}

type SequenceValidator struct {
	seen bool
	last uint64
}

type SequenceWindow struct {
	seen    bool
	highest uint64
	bitmap  uint64
}

func (window *SequenceWindow) Accept(sequence uint64) error {
	if !window.seen {
		window.seen = true
		window.highest = sequence
		window.bitmap = 1
		return nil
	}
	if sequence > window.highest {
		shift := sequence - window.highest
		if shift >= 64 {
			window.bitmap = 0
		} else {
			window.bitmap <<= shift
		}
		window.bitmap |= 1
		window.highest = sequence
		return nil
	}
	distance := window.highest - sequence
	if distance >= 64 || window.bitmap&(uint64(1)<<distance) != 0 {
		return ErrNonMonotonic
	}
	window.bitmap |= uint64(1) << distance
	return nil
}

func (validator *SequenceValidator) Accept(sequence uint64) error {
	if validator.seen && sequence <= validator.last {
		return ErrNonMonotonic
	}
	validator.seen = true
	validator.last = sequence
	return nil
}

type boundedReader struct {
	data []byte
}

func (reader *boundedReader) Read(destination []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	count := copy(destination, reader.data)
	reader.data = reader.data[count:]
	return count, nil
}
