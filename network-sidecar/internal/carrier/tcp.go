package carrier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const defaultDialTimeout = 10 * time.Second

var ErrInvalidEndpoint = errors.New("invalid carrier endpoint")

type TCPConfig struct {
	Address    string
	ServerName string
	RootCAs    *x509.CertPool
	Timeout    time.Duration
}

func DialTCP(ctx context.Context, config TCPConfig) (*Stream, error) {
	if err := validateTCPConfig(config); err != nil {
		return nil, err
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultDialTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", config.Address)
	if err != nil {
		return nil, fmt.Errorf("dial TCP carrier: %w", err)
	}
	tlsConnection := tls.Client(connection, &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: config.ServerName,
		RootCAs:    config.RootCAs,
	})
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("authenticate TCP carrier: %w", err)
	}
	return NewStream(tlsConnection), nil
}

func validateTCPConfig(config TCPConfig) error {
	if strings.TrimSpace(config.Address) != config.Address || config.Address == "" {
		return ErrInvalidEndpoint
	}
	host, port, err := net.SplitHostPort(config.Address)
	if err != nil || host == "" || port == "" {
		return ErrInvalidEndpoint
	}
	if strings.TrimSpace(config.ServerName) != config.ServerName || config.ServerName == "" {
		return ErrInvalidEndpoint
	}
	if config.Timeout < 0 {
		return ErrInvalidEndpoint
	}
	return nil
}
