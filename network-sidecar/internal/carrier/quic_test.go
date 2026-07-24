package carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"os"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

func TestQUICCarrierAuthenticatesAndReassemblesLargePacket(t *testing.T) {
	testTimeout := 5 * time.Second
	if os.Getenv("KYCLASH_LAB_IMPAIRED") == "1" {
		testTimeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
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
		connection, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		server := newQUIC(connection)
		defer server.Close()
		packet, receiveErr := server.Receive(ctx)
		if receiveErr == nil {
			receiveErr = server.Send(ctx, packet)
		}
		if receiveErr == nil {
			time.Sleep(20 * time.Millisecond)
		}
		serverResult <- receiveErr
	}()
	client, err := DialQUIC(ctx, QUICConfig{
		Address:    listener.Addr().String(),
		ServerName: "127.0.0.1",
		RootCAs:    roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	clientReceived := make(chan []byte, 1)
	clientReceiveErr := make(chan error, 1)
	go func() {
		value, receiveErr := client.Receive(ctx)
		if receiveErr != nil {
			clientReceiveErr <- receiveErr
			return
		}
		clientReceived <- value
	}()
	if latency, err := client.Probe(ctx); err != nil || latency < 0 {
		t.Fatalf("live QUIC ping/pong failed: latency=%v err=%v", latency, err)
	}
	packet := bytes.Repeat([]byte{1, 2, 3}, 1_000)
	if err := client.Send(ctx, packet); err != nil {
		t.Fatal(err)
	}
	var received []byte
	select {
	case received = <-clientReceived:
	case err = <-clientReceiveErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !bytes.Equal(received, packet) {
		t.Fatal("reassembled packet mismatch")
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestQUICLabUDPBlocked(t *testing.T) {
	if os.Getenv("KYCLASH_LAB_EXPECT_QUIC_BLOCKED") != "1" {
		t.Skip("Linux VM impairment lab only")
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	connection, err := DialQUIC(ctx, QUICConfig{
		Address:    listener.Addr().String(),
		ServerName: "127.0.0.1",
		RootCAs:    roots,
		Timeout:    500 * time.Millisecond,
	})
	if connection != nil {
		_ = connection.Close()
	}
	if err == nil {
		t.Fatal("expected QUIC connection refusal while the Linux lab blocks UDP")
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

func TestQUICCarrierUsesMutualTLSWithExactTLS13(t *testing.T) {
	fixture := testMutualTLSCertificates(t, "127.0.0.1")
	listener, err := quicgo.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{fixture.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    fixture.roots,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{quicALPN},
	}, &quicgo.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverResult := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer connection.CloseWithError(0, "")
		state := connection.ConnectionState().TLS
		if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) != 1 ||
			state.PeerCertificates[0].Subject.CommonName != "kyclash-client.test" {
			serverResult <- errors.New("unexpected mutual TLS client identity")
			return
		}
		serverResult <- nil
	}()

	client, err := DialQUIC(ctx, QUICConfig{
		Address:           listener.Addr().String(),
		ServerName:        "127.0.0.1",
		RootCAs:           fixture.roots,
		ClientCertificate: &fixture.client,
		ExactTLS13:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.connection.ConnectionState().TLS.Version != tls.VersionTLS13 {
		t.Fatal("QUIC client did not negotiate TLS 1.3")
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestQUICReceiveCancellationIsBounded(t *testing.T) {
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
	accepted := make(chan *quicgo.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept(context.Background())
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- connection
	}()

	client, err := DialQUIC(context.Background(), QUICConfig{
		Address:    listener.Addr().String(),
		ServerName: "127.0.0.1",
		RootCAs:    roots,
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var serverConnection *quicgo.Conn
	select {
	case serverConnection = <-accepted:
		defer serverConnection.CloseWithError(0, "")
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("QUIC server did not accept the authenticated connection")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = client.Receive(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected receive deadline, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("receive cancellation was not bounded: %v", elapsed)
	}
}

func TestQUICAbruptPeerCloseUnblocksReceive(t *testing.T) {
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
	accepted := make(chan *quicgo.Conn, 1)
	go func() {
		connection, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		accepted <- connection
	}()

	client, err := DialQUIC(context.Background(), QUICConfig{
		Address:    listener.Addr().String(),
		ServerName: "127.0.0.1",
		RootCAs:    roots,
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case serverConnection := <-accepted:
		if err := serverConnection.CloseWithError(42, "lab abort"); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("QUIC server did not accept the authenticated connection")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.Receive(ctx); err == nil {
		t.Fatal("expected abrupt peer close to fail receive")
	}
}

func TestQUICConfigAndPacketBoundsFailClosed(t *testing.T) {
	for _, config := range []QUICConfig{
		{},
		{Address: "example.test:443"},
		{Address: "example.test", ServerName: "example.test"},
		{Address: "example.test:443", ServerName: "example.test", Timeout: -1},
		{Address: "example.test:443", ServerName: "example.test", ClientCertificate: &tls.Certificate{}},
	} {
		if _, err := DialQUIC(context.Background(), config); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("expected validation refusal for %#v, got %v", config, err)
		}
	}
}
