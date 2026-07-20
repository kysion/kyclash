package carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

func TestQUICCarrierAuthenticatesAndReassemblesLargePacket(t *testing.T) {
	certificate, roots := testCertificate(t, "127.0.0.1")
	listener, err := quicgo.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{quicALPN},
	}, &quicgo.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		server := newQUIC(connection)
		defer server.Close()
		packet, receiveErr := server.Receive(context.Background())
		if receiveErr == nil {
			receiveErr = server.Send(context.Background(), packet)
		}
		if receiveErr == nil {
			time.Sleep(20 * time.Millisecond)
		}
		serverResult <- receiveErr
	}()
	client, err := DialQUIC(context.Background(), QUICConfig{
		Address:    listener.Addr().String(),
		ServerName: "127.0.0.1",
		RootCAs:    roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	packet := bytes.Repeat([]byte{1, 2, 3}, 1_000)
	if err := client.Send(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	received, err := client.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, packet) {
		t.Fatal("reassembled packet mismatch")
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestQUICCarrierRejectsWrongIdentity(t *testing.T) {
	certificate, roots := testCertificate(t, "sidecar.test")
	listener, err := quicgo.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{quicALPN},
	}, &quicgo.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = DialQUIC(ctx, QUICConfig{
		Address:    listener.Addr().String(),
		ServerName: "attacker.test",
		RootCAs:    roots,
	})
	if err == nil {
		t.Fatal("expected server identity refusal")
	}
}

func TestQUICConfigAndPacketBoundsFailClosed(t *testing.T) {
	for _, config := range []QUICConfig{
		{},
		{Address: "example.test:443"},
		{Address: "example.test", ServerName: "example.test"},
		{Address: "example.test:443", ServerName: "example.test", Timeout: -1},
	} {
		if _, err := DialQUIC(context.Background(), config); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("expected validation refusal for %#v, got %v", config, err)
		}
	}
}
