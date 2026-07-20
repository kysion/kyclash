// Package wgcarrier adapts the KyClash packet carrier to wireguard-go's
// replaceable conn.Bind interface. It does not create a TUN device or routes.
package wgcarrier

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
	"golang.zx2c4.com/wireguard/conn"
)

var (
	ErrInvalidEndpoint = errors.New("invalid WireGuard carrier endpoint")
	ErrPacketBuffer    = errors.New("WireGuard receive buffer too small")
)

type Bind struct {
	carrier carrier.Carrier
	remote  endpoint
	mu      sync.Mutex
	opened  bool
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewBind(packetCarrier carrier.Carrier, endpointID string) (*Bind, error) {
	remote, err := parseEndpoint(endpointID)
	if err != nil {
		return nil, err
	}
	return &Bind{carrier: packetCarrier, remote: remote}, nil
}

func (bind *Bind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if bind.opened && !bind.closed {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if bind.closed {
		return nil, 0, net.ErrClosed
	}
	bind.ctx, bind.cancel = context.WithCancel(context.Background())
	bind.opened = true
	return []conn.ReceiveFunc{bind.receive}, 0, nil
}

func (bind *Bind) receive(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
	bind.mu.Lock()
	ctx := bind.ctx
	closed := bind.closed
	bind.mu.Unlock()
	if closed || ctx == nil {
		return 0, net.ErrClosed
	}
	if len(packets) == 0 || len(sizes) == 0 || len(endpoints) == 0 {
		return 0, ErrPacketBuffer
	}
	packet, err := bind.carrier.Receive(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || bind.isClosed() {
			return 0, net.ErrClosed
		}
		return 0, err
	}
	if len(packet) > len(packets[0]) {
		return 0, ErrPacketBuffer
	}
	copy(packets[0], packet)
	sizes[0] = len(packet)
	endpoints[0] = bind.remote
	return 1, nil
}

func (bind *Bind) Close() error {
	bind.mu.Lock()
	if bind.closed {
		bind.mu.Unlock()
		return nil
	}
	bind.closed = true
	if bind.cancel != nil {
		bind.cancel()
	}
	bind.mu.Unlock()
	return bind.carrier.Close()
}

func (bind *Bind) SetMark(uint32) error {
	return nil
}

func (bind *Bind) Send(buffers [][]byte, destination conn.Endpoint) error {
	bind.mu.Lock()
	ctx := bind.ctx
	active := bind.opened && !bind.closed && ctx != nil
	bind.mu.Unlock()
	if !active {
		return net.ErrClosed
	}
	remote, ok := destination.(endpoint)
	if !ok || remote.id != bind.remote.id {
		return conn.ErrWrongEndpointType
	}
	for _, packet := range buffers {
		if err := bind.carrier.Send(ctx, packet); err != nil {
			return err
		}
	}
	return nil
}

func (bind *Bind) ParseEndpoint(value string) (conn.Endpoint, error) {
	parsed, err := parseEndpoint(value)
	if err != nil {
		return nil, err
	}
	if parsed.id != bind.remote.id {
		return nil, ErrInvalidEndpoint
	}
	return parsed, nil
}

func (*Bind) BatchSize() int {
	return 1
}

func (bind *Bind) isClosed() bool {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	return bind.closed
}

type endpoint struct {
	id string
}

func parseEndpoint(value string) (endpoint, error) {
	if value == "" || len(value) > 255 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t") {
		return endpoint{}, ErrInvalidEndpoint
	}
	return endpoint{id: value}, nil
}

func (endpoint) ClearSrc() {}

func (endpoint) SrcToString() string { return "" }

func (value endpoint) DstToString() string { return value.id }

func (value endpoint) DstToBytes() []byte { return []byte(value.id) }

func (endpoint) DstIP() netip.Addr { return netip.Addr{} }

func (endpoint) SrcIP() netip.Addr { return netip.Addr{} }

var _ conn.Bind = (*Bind)(nil)
var _ conn.Endpoint = endpoint{}
