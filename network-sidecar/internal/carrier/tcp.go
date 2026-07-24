package carrier

import (
	"context"
	"crypto"
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
	Address           string
	ServerName        string
	RootCAs           *x509.CertPool
	ClientCertificate *tls.Certificate
	ExactTLS13        bool
	Timeout           time.Duration
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
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: config.ServerName,
		RootCAs:    config.RootCAs,
	}
	applyClientTLSOptions(tlsConfig, config.ClientCertificate, config.ExactTLS13)
	tlsConnection := tls.Client(connection, tlsConfig)
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
	if config.Timeout < 0 || !validClientCertificate(config.ClientCertificate) {
		return ErrInvalidEndpoint
	}
	return nil
}

func applyClientTLSOptions(config *tls.Config, certificate *tls.Certificate, exactTLS13 bool) {
	if certificate != nil {
		config.Certificates = []tls.Certificate{*certificate}
	}
	if exactTLS13 {
		config.MaxVersion = tls.VersionTLS13
	}
}

func validClientCertificate(certificate *tls.Certificate) bool {
	if certificate == nil {
		return true
	}
	_, signer := certificate.PrivateKey.(crypto.Signer)
	return len(certificate.Certificate) != 0 && signer
}
