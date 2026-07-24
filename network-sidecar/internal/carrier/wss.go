package carrier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"
)

type WSSConfig struct {
	URL               string
	RootCAs           *x509.CertPool
	ClientCertificate *tls.Certificate
	ExactTLS13        bool
	Timeout           time.Duration
}

func DialWSS(ctx context.Context, config WSSConfig) (*Stream, error) {
	if err := validateWSSConfig(config); err != nil {
		return nil, err
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultDialTimeout
	}
	dialContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    config.RootCAs,
	}
	applyClientTLSOptions(tlsConfig, config.ClientCertificate, config.ExactTLS13)
	connection, response, err := websocket.Dial(dialContext, config.URL, &websocket.DialOptions{
		HTTPClient:      &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, fmt.Errorf("dial WSS carrier: %w", err)
	}
	return NewStream(websocket.NetConn(context.Background(), connection, websocket.MessageBinary)), nil
}

func validateWSSConfig(config WSSConfig) error {
	if config.Timeout < 0 || !validClientCertificate(config.ClientCertificate) {
		return ErrInvalidEndpoint
	}
	parsed, err := url.Parse(config.URL)
	if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.Hostname() == "" {
		return ErrInvalidEndpoint
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return ErrInvalidEndpoint
	}
	return nil
}
