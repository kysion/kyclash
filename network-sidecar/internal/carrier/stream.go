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
	probe      probeState
}

func NewStream(connection net.Conn) *Stream {
	return &Stream{connection: connection, closed: make(chan struct{}), probe: newProbeState()}
}

func (stream *Stream) Send(ctx context.Context, packet []byte) error {
	_, err := stream.sendFrame(ctx, frame.KindWireGuardPacket, packet)
	return err
}

func (stream *Stream) sendFrame(ctx context.Context, kind frame.Kind, payload []byte) (bool, error) {
	stream.writeMu.Lock()
	defer stream.writeMu.Unlock()
	if stream.isClosed() {
		return false, ErrClosed
	}
	if stream.next == ^uint64(0) {
		return false, ErrSequenceExhaust
	}
	encoded, err := frame.Encode(frame.Frame{
		Kind:     kind,
		Sequence: stream.next,
		Payload:  payload,
	})
	if err != nil {
		return false, err
	}
	dispatched := false
	if err := stream.withWriteContext(ctx, func() error {
		dispatched = true
		return writeFull(stream.connection, encoded)
	}); err != nil {
		return dispatched, err
	}
	stream.next++
	return true, nil
}

func (stream *Stream) Probe(ctx context.Context) (time.Duration, error) {
	return stream.probe.measure(ctx, stream.closed, func(ctx context.Context) (bool, error) {
		return stream.sendFrame(ctx, frame.KindPing, nil)
	})
}

func (stream *Stream) Receive(ctx context.Context) ([]byte, error) {
	stream.readMu.Lock()
	defer stream.readMu.Unlock()
	if stream.isClosed() {
		return nil, ErrClosed
	}
	for {
		var decoded frame.Frame
		err := stream.withReadContext(ctx, func() error {
			var decodeErr error
			decoded, decodeErr = frame.Decode(stream.connection)
			return decodeErr
		})
		if err != nil {
			return nil, err
		}
		if err := stream.incoming.Accept(decoded.Sequence); err != nil {
			return nil, err
		}
		switch decoded.Kind {
		case frame.KindWireGuardPacket:
			if decoded.Fragment != nil {
				return nil, ErrUnexpectedFrame
			}
			return decoded.Payload, nil
		case frame.KindPing:
			replyContext, cancel := context.WithTimeout(ctx, time.Second)
			_, err := stream.sendFrame(replyContext, frame.KindPong, nil)
			cancel()
			if err != nil {
				return nil, err
			}
		case frame.KindPong:
			stream.probe.observePong()
		case frame.KindClose:
			return nil, ErrClosed
		default:
			return nil, ErrUnexpectedFrame
		}
	}
}

func (stream *Stream) Close() error {
	var closeErr error
	stream.closeOnce.Do(func() {
		close(stream.closed)
		closeErr = stream.connection.Close()
	})
	return closeErr
}

var _ Prober = (*Stream)(nil)

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
