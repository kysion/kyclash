package carrier

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

func TestWSSCarrierAuthenticatesTLSAndExchangesPacket(t *testing.T) {
	certificate, roots := testCertificate(t, "127.0.0.1")
	serverResult := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			serverResult <- err
			return
		}
		stream := NewStream(websocket.NetConn(context.Background(), connection, websocket.MessageBinary))
		defer stream.Close()
		packet, err := stream.Receive(context.Background())
		if err == nil {
			err = stream.Send(context.Background(), packet)
		}
		serverResult <- err
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	client, err := DialWSS(context.Background(), WSSConfig{
		URL:     "wss" + strings.TrimPrefix(server.URL, "https"),
		RootCAs: roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Send(context.Background(), []byte("packet")); err != nil {
		t.Fatal(err)
	}
	packet, err := client.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(packet) != "packet" {
		t.Fatalf("unexpected packet: %q", packet)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestWSSCarrierRejectsWrongServerIdentity(t *testing.T) {
	certificate, roots := testCertificate(t, "sidecar.test")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = websocket.Accept(response, request, nil)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	_, err := DialWSS(context.Background(), WSSConfig{
		URL:     "wss" + strings.TrimPrefix(server.URL, "https"),
		RootCAs: roots,
	})
	if err == nil {
		t.Fatal("expected server identity refusal")
	}
}

func TestWSSConfigFailsClosed(t *testing.T) {
	for _, config := range []WSSConfig{
		{},
		{URL: "ws://example.test/tunnel"},
		{URL: "wss://user@example.test/tunnel"},
		{URL: "wss://example.test/tunnel?token=secret"},
		{URL: "wss://example.test/tunnel#fragment"},
		{URL: "wss://example.test/tunnel", Timeout: -1},
	} {
		if _, err := DialWSS(context.Background(), config); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("expected validation refusal for %#v, got %v", config, err)
		}
	}
}
