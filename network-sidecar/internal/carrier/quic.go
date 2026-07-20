package carrier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/frame"
	quicgo "github.com/quic-go/quic-go"
)

const (
	quicALPN               = "kyclash-network/1"
	quicFragmentPayloadMax = 1_024
	fragmentAssemblyTTL    = 10 * time.Second
)

var ErrDatagramsUnavailable = errors.New("QUIC peer does not support datagrams")

type QUICConfig struct {
	Address    string
	ServerName string
	RootCAs    *x509.CertPool
	Timeout    time.Duration
}

type QUIC struct {
	connection  *quicgo.Conn
	writeMu     sync.Mutex
	readMu      sync.Mutex
	closeOnce   sync.Once
	closed      chan struct{}
	next        uint64
	nextMessage uint64
	incoming    frame.SequenceWindow
	reassembler *frame.Reassembler
}

func DialQUIC(ctx context.Context, config QUICConfig) (*QUIC, error) {
	if err := validateQUICConfig(config); err != nil {
		return nil, err
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultDialTimeout
	}
	dialContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := quicgo.DialAddr(dialContext, config.Address, &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: config.ServerName,
		RootCAs:    config.RootCAs,
		NextProtos: []string{quicALPN},
	}, &quicgo.Config{
		EnableDatagrams:      true,
		HandshakeIdleTimeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("dial QUIC carrier: %w", err)
	}
	datagramSupport := connection.ConnectionState().SupportsDatagrams
	if !datagramSupport.Local || !datagramSupport.Remote {
		_ = connection.CloseWithError(0, "datagrams required")
		return nil, ErrDatagramsUnavailable
	}
	return newQUIC(connection), nil
}

func newQUIC(connection *quicgo.Conn) *QUIC {
	return &QUIC{
		connection:  connection,
		closed:      make(chan struct{}),
		reassembler: frame.NewReassembler(fragmentAssemblyTTL),
	}
}

func (carrier *QUIC) Send(ctx context.Context, packet []byte) error {
	carrier.writeMu.Lock()
	defer carrier.writeMu.Unlock()
	if carrier.isClosed() {
		return ErrClosed
	}
	if len(packet) > frame.MaxPayloadSize {
		return frame.ErrPayloadTooLarge
	}
	fragmentCount := 1
	if len(packet) > quicFragmentPayloadMax {
		fragmentCount = (len(packet) + quicFragmentPayloadMax - 1) / quicFragmentPayloadMax
	}
	if fragmentCount > frame.MaxFragments || carrier.next > ^uint64(0)-uint64(fragmentCount) {
		return ErrSequenceExhaust
	}
	messageID := carrier.nextMessage
	if fragmentCount > 1 && messageID == ^uint64(0) {
		return ErrSequenceExhaust
	}
	for index := range fragmentCount {
		if err := ctx.Err(); err != nil {
			return err
		}
		start := index * quicFragmentPayloadMax
		end := min(start+quicFragmentPayloadMax, len(packet))
		outgoing := frame.Frame{
			Kind:     frame.KindWireGuardPacket,
			Sequence: carrier.next,
			Payload:  packet[start:end],
		}
		if fragmentCount > 1 {
			outgoing.Fragment = &frame.Fragment{
				MessageID: messageID,
				Index:     uint16(index),
				Count:     uint16(fragmentCount),
			}
		}
		encoded, err := frame.Encode(outgoing)
		if err != nil {
			return err
		}
		if err := carrier.connection.SendDatagram(encoded); err != nil {
			return fmt.Errorf("send QUIC datagram: %w", err)
		}
		carrier.next++
	}
	if fragmentCount > 1 {
		carrier.nextMessage++
	}
	return nil
}

func (carrier *QUIC) Receive(ctx context.Context) ([]byte, error) {
	carrier.readMu.Lock()
	defer carrier.readMu.Unlock()
	if carrier.isClosed() {
		return nil, ErrClosed
	}
	for {
		datagram, err := carrier.connection.ReceiveDatagram(ctx)
		if err != nil {
			return nil, fmt.Errorf("receive QUIC datagram: %w", err)
		}
		decoded, err := frame.DecodeDatagram(datagram)
		if err != nil {
			return nil, err
		}
		if decoded.Kind != frame.KindWireGuardPacket {
			return nil, ErrUnexpectedFrame
		}
		if err := carrier.incoming.Accept(decoded.Sequence); err != nil {
			return nil, err
		}
		packet, complete, err := carrier.reassembler.Accept(decoded)
		if err != nil {
			return nil, err
		}
		if complete {
			return packet, nil
		}
	}
}

func (carrier *QUIC) Close() error {
	var closeErr error
	carrier.closeOnce.Do(func() {
		close(carrier.closed)
		carrier.reassembler.Reset()
		closeErr = carrier.connection.CloseWithError(0, "")
	})
	return closeErr
}

func (carrier *QUIC) isClosed() bool {
	select {
	case <-carrier.closed:
		return true
	default:
		return false
	}
}

func validateQUICConfig(config QUICConfig) error {
	if config.Timeout < 0 || config.Address == "" || config.ServerName == "" {
		return ErrInvalidEndpoint
	}
	host, port, err := net.SplitHostPort(config.Address)
	if err != nil || host == "" || port == "" {
		return ErrInvalidEndpoint
	}
	return nil
}
