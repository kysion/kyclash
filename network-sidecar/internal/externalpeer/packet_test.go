package externalpeer

import (
	"context"
	"net"
	"sync"
	"time"
)

type scriptedPacketConn struct {
	mu      sync.Mutex
	packets [][]byte
	closed  bool
}

func (connection *scriptedPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if len(connection.packets) == 0 {
		return 0, nil, net.ErrClosed
	}
	packet := connection.packets[0]
	connection.packets = connection.packets[1:]
	return copy(buffer, packet), testPacketAddress("192.168.64.11:40000"), nil
}

func (connection *scriptedPacketConn) WriteTo(buffer []byte, _ net.Addr) (int, error) {
	if connection.closed {
		return 0, net.ErrClosed
	}
	return len(buffer), nil
}
func (connection *scriptedPacketConn) Close() error {
	connection.closed = true
	return nil
}
func (connection *scriptedPacketConn) LocalAddr() net.Addr {
	return testPacketAddress("192.168.64.22:22001")
}
func (connection *scriptedPacketConn) SetDeadline(time.Time) error      { return nil }
func (connection *scriptedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (connection *scriptedPacketConn) SetWriteDeadline(time.Time) error { return nil }

type testPacketAddress string

func (address testPacketAddress) Network() string { return "udp" }
func (address testPacketAddress) String() string  { return string(address) }

type recordingPacketCarrier struct {
	closeCount int
}

func (carrier *recordingPacketCarrier) Send(context.Context, []byte) error { return nil }
func (carrier *recordingPacketCarrier) Receive(context.Context) ([]byte, error) {
	return nil, net.ErrClosed
}
func (carrier *recordingPacketCarrier) Close() error {
	carrier.closeCount++
	return nil
}
