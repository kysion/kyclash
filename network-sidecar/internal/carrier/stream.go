package carrier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/frame"
)

var (
	ErrClosed          = errors.New("carrier closed")
	ErrSequenceExhaust = errors.New("carrier sequence exhausted")
	ErrUnexpectedFrame = errors.New("unexpected carrier control frame")
)

// Stream adapts a reliable byte stream, including TLS, WSS net.Conn wrappers,
// and plain TCP, to the packet-oriented Carrier contract.
type Stream struct {
	connection net.Conn
	readMu     sync.Mutex
	writeMu    sync.Mutex
	closeOnce  sync.Once
	closed     chan struct{}
	next       uint64
	incoming   frame.SequenceValidator
}

func NewStream(connection net.Conn) *Stream {
	return &Stream{connection: connection, closed: make(chan struct{})}
}

func (stream *Stream) Send(ctx context.Context, packet []byte) error {
	stream.writeMu.Lock()
	defer stream.writeMu.Unlock()
	if stream.isClosed() {
		return ErrClosed
	}
	if stream.next == ^uint64(0) {
		return ErrSequenceExhaust
	}
	encoded, err := frame.Encode(frame.Frame{
		Kind:     frame.KindWireGuardPacket,
		Sequence: stream.next,
		Payload:  packet,
	})
	if err != nil {
		return err
	}
	if err := stream.withWriteContext(ctx, func() error { return writeFull(stream.connection, encoded) }); err != nil {
		return err
	}
	stream.next++
	return nil
}

func (stream *Stream) Receive(ctx context.Context) ([]byte, error) {
	stream.readMu.Lock()
	defer stream.readMu.Unlock()
	if stream.isClosed() {
		return nil, ErrClosed
	}
	var decoded frame.Frame
	err := stream.withReadContext(ctx, func() error {
		var decodeErr error
		decoded, decodeErr = frame.Decode(stream.connection)
		return decodeErr
	})
	if err != nil {
		return nil, err
	}
	if decoded.Kind != frame.KindWireGuardPacket {
		return nil, ErrUnexpectedFrame
	}
	if err := stream.incoming.Accept(decoded.Sequence); err != nil {
		return nil, err
	}
	return decoded.Payload, nil
}

func (stream *Stream) Close() error {
	var closeErr error
	stream.closeOnce.Do(func() {
		close(stream.closed)
		closeErr = stream.connection.Close()
	})
	return closeErr
}

func (stream *Stream) isClosed() bool {
	select {
	case <-stream.closed:
		return true
	default:
		return false
	}
}

func (stream *Stream) withReadContext(ctx context.Context, operation func() error) error {
	return withContext(ctx, stream.connection.SetReadDeadline, operation)
}

func (stream *Stream) withWriteContext(ctx context.Context, operation func() error) error {
	return withContext(ctx, stream.connection.SetWriteDeadline, operation)
}

func withContext(ctx context.Context, setDeadline func(time.Time) error, operation func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := setDeadline(deadline); err != nil {
			return fmt.Errorf("set carrier deadline: %w", err)
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = setDeadline(time.Now()) })
	err := operation()
	stoppedBeforeCancel := stop()
	_ = setDeadline(time.Time{})
	if !stoppedBeforeCancel && ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	return nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[written:]
	}
	return nil
}
