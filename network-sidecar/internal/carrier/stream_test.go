package carrier

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/frame"
)

type firstWriteGate struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (connection *firstWriteGate) Write(data []byte) (int, error) {
	connection.once.Do(func() {
		close(connection.started)
		<-connection.release
	})
	return connection.Conn.Write(data)
}

type completedWriteCancellationConn struct {
	net.Conn
	mu                 sync.Mutex
	writes             [][]byte
	firstWriteStarted  chan struct{}
	releaseFirstWrite  chan struct{}
	cancelDeadlineSet  chan struct{}
	firstWriteOnce     sync.Once
	cancelDeadlineOnce sync.Once
}

func (connection *completedWriteCancellationConn) Write(data []byte) (int, error) {
	connection.mu.Lock()
	connection.writes = append(connection.writes, bytes.Clone(data))
	writeIndex := len(connection.writes) - 1
	connection.mu.Unlock()
	if writeIndex == 0 {
		connection.firstWriteOnce.Do(func() { close(connection.firstWriteStarted) })
		<-connection.releaseFirstWrite
	}
	return len(data), nil
}

func (connection *completedWriteCancellationConn) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		connection.cancelDeadlineOnce.Do(func() { close(connection.cancelDeadlineSet) })
	}
	return nil
}

func (connection *completedWriteCancellationConn) capturedWrites() [][]byte {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	result := make([][]byte, len(connection.writes))
	for index := range connection.writes {
		result[index] = bytes.Clone(connection.writes[index])
	}
	return result
}

type blockingDeadlineSetter struct {
	mu                sync.Mutex
	deadline          time.Time
	cancelEntered     chan struct{}
	releaseCancel     chan struct{}
	cancelEnteredOnce sync.Once
}

func (setter *blockingDeadlineSetter) set(deadline time.Time) error {
	if !deadline.IsZero() {
		setter.cancelEnteredOnce.Do(func() {
			close(setter.cancelEntered)
			<-setter.releaseCancel
		})
	}
	setter.mu.Lock()
	setter.deadline = deadline
	setter.mu.Unlock()
	return nil
}

func (setter *blockingDeadlineSetter) current() time.Time {
	setter.mu.Lock()
	defer setter.mu.Unlock()
	return setter.deadline
}

func TestCompletedStreamWriteAdvancesSequenceWhenCancellationWins(t *testing.T) {
	connection := &completedWriteCancellationConn{
		firstWriteStarted: make(chan struct{}),
		releaseFirstWrite: make(chan struct{}),
		cancelDeadlineSet: make(chan struct{}),
	}
	stream := NewStream(connection)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := stream.sendFrame(ctx, frame.KindPing, nil)
		first <- err
	}()
	<-connection.firstWriteStarted
	cancel()
	<-connection.cancelDeadlineSet
	close(connection.releaseFirstWrite)
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("completed write cancellation returned %v", err)
	}
	if dispatched, err := stream.sendFrame(context.Background(), frame.KindPing, nil); err != nil || !dispatched {
		t.Fatalf("next write failed after completed cancellation: dispatched=%v err=%v", dispatched, err)
	}
	writes := connection.capturedWrites()
	if len(writes) != 2 {
		t.Fatalf("expected two captured frames, got %d", len(writes))
	}
	for index, encoded := range writes {
		decoded, err := frame.Decode(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("decode frame %d: %v", index, err)
		}
		if decoded.Sequence != uint64(index) {
			t.Fatalf("frame %d reused sequence %d", index, decoded.Sequence)
		}
	}
}

func TestWithContextWaitsForCancellationDeadlineBeforeReset(t *testing.T) {
	setter := &blockingDeadlineSetter{
		cancelEntered: make(chan struct{}),
		releaseCancel: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	operationStarted := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- withContext(ctx, setter.set, func() error {
			close(operationStarted)
			<-setter.cancelEntered
			return nil
		})
	}()
	<-operationStarted
	cancel()
	<-setter.cancelEntered
	select {
	case err := <-result:
		close(setter.releaseCancel)
		t.Fatalf("withContext returned before cancellation deadline completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(setter.releaseCancel)
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("withContext cancellation returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("withContext did not join cancellation deadline callback")
	}
	if deadline := setter.current(); !deadline.IsZero() {
		t.Fatalf("cancellation deadline survived reset: %v", deadline)
	}
}

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

func TestSendCancellationUnblocksBlockedStreamWrite(t *testing.T) {
	leftConnection, rightConnection := net.Pipe()
	left := NewStream(leftConnection)
	defer left.Close()
	defer rightConnection.Close()

	// net.Pipe has no buffering.  With no reader on the other side the write
	// must remain blocked until the operation deadline; this exercises the
	// same cancellation path used by the WSS and TLS/TCP carriers.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := left.Send(ctx, []byte("blocked"))
	var networkError net.Error
	if !errors.Is(err, context.DeadlineExceeded) && (!errors.As(err, &networkError) || !networkError.Timeout()) {
		t.Fatalf("expected write deadline, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("blocked write was not bounded: %v", elapsed)
	}
}

func TestReceiveRejectsReplay(t *testing.T) {
	writer, reader := net.Pipe()
	stream := NewStream(reader)
	defer stream.Close()
	go func() {
		defer writer.Close()
		for _, item := range []frame.Frame{{Kind: frame.KindWireGuardPacket, Sequence: 2}, {Kind: frame.KindWireGuardPacket, Sequence: 2}} {
			encoded, err := frame.Encode(item)
			if err != nil {
				return
			}
			_ = writeFull(writer, encoded)
		}
	}()
	if _, err := stream.Receive(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Receive(context.Background()); !errors.Is(err, frame.ErrNonMonotonic) {
		t.Fatalf("expected %v, got %v", frame.ErrNonMonotonic, err)
	}
}

func TestStreamProbeUsesPayloadFreePingPongWithoutConsumingPackets(t *testing.T) {
	leftConnection, rightConnection := net.Pipe()
	left := NewStream(leftConnection)
	right := NewStream(rightConnection)
	defer left.Close()
	defer right.Close()
	leftReceive := make(chan error, 1)
	go func() {
		_, err := left.Receive(context.Background())
		leftReceive <- err
	}()
	rightPacket := make(chan []byte, 1)
	rightError := make(chan error, 1)
	go func() {
		packet, err := right.Receive(context.Background())
		if err != nil {
			rightError <- err
			return
		}
		rightPacket <- packet
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	latency, err := left.Probe(ctx)
	if err != nil || latency < 0 {
		t.Fatalf("probe failed: latency=%v err=%v", latency, err)
	}
	want := []byte("encrypted-after-health")
	if err := left.Send(ctx, want); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-rightPacket:
		if !bytes.Equal(got, want) {
			t.Fatalf("packet mismatch after control exchange: %q", got)
		}
	case err := <-rightError:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_ = left.Close()
	select {
	case <-leftReceive:
	case <-time.After(time.Second):
		t.Fatal("receive did not unblock after close")
	}
}

func TestStreamProbeTimeoutFailsClosedForConnectionLifetime(t *testing.T) {
	leftConnection, rightConnection := net.Pipe()
	stream := NewStream(leftConnection)
	defer stream.Close()
	defer rightConnection.Close()
	received := make(chan error, 1)
	go func() {
		decoded, err := frame.Decode(rightConnection)
		if err == nil && decoded.Kind != frame.KindPing {
			err = ErrUnexpectedFrame
		}
		received <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := stream.Probe(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected bounded probe timeout, got %v", err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := stream.Probe(context.Background()); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("expected terminal ambiguous-probe refusal, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("terminal probe refusal was not immediate: %v", elapsed)
	}
}

func TestStreamProbeCancellationDrainsPongAndRemainsReusable(t *testing.T) {
	leftConnection, rightConnection := net.Pipe()
	left := NewStream(leftConnection)
	gate := &firstWriteGate{Conn: rightConnection, started: make(chan struct{}), release: make(chan struct{})}
	right := NewStream(gate)
	defer left.Close()
	defer right.Close()

	ctx, cancelReceivers := context.WithCancel(context.Background())
	defer cancelReceivers()
	leftReceive := make(chan error, 1)
	rightReceive := make(chan error, 1)
	go func() { _, err := left.Receive(ctx); leftReceive <- err }()
	go func() { _, err := right.Receive(ctx); rightReceive <- err }()

	probeContext, cancelProbe := context.WithCancel(context.Background())
	firstProbe := make(chan error, 1)
	go func() { _, err := left.Probe(probeContext); firstProbe <- err }()
	select {
	case <-gate.started:
	case <-time.After(time.Second):
		t.Fatal("peer did not begin delayed Pong")
	}
	cancelProbe()
	close(gate.release)
	select {
	case err := <-firstProbe:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled probe returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled probe did not drain its Pong")
	}

	secondContext, cancelSecond := context.WithTimeout(context.Background(), time.Second)
	defer cancelSecond()
	if _, err := left.Probe(secondContext); err != nil {
		t.Fatalf("drained cancellation poisoned the next probe: %v", err)
	}
	cancelReceivers()
	_ = left.Close()
	_ = right.Close()
	select {
	case <-leftReceive:
	case <-time.After(time.Second):
		t.Fatal("left receiver did not join")
	}
	select {
	case <-rightReceive:
	case <-time.After(time.Second):
		t.Fatal("right receiver did not join")
	}
}

func TestProbeCancellationDrainTimeoutRejectsLatePong(t *testing.T) {
	state := newProbeState()
	closed := make(chan struct{})
	probeContext, cancelProbe := context.WithCancel(context.Background())
	sent := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := state.measure(probeContext, closed, func(context.Context) (bool, error) {
			close(sent)
			return true, nil
		})
		result <- err
	}()
	<-sent
	cancelProbe()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ambiguous cancelled probe returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ambiguous probe cancellation escaped drain bound")
	}
	state.observePong()
	if _, err := state.measure(context.Background(), closed, func(context.Context) (bool, error) {
		t.Fatal("late Pong was misassociated with a new probe")
		return false, nil
	}); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("ambiguous probe did not remain fail-closed: %v", err)
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
