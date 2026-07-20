package carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"testing"

	quicgo "github.com/quic-go/quic-go"
)

func BenchmarkQUICCarrierFragmentedRoundTrip(b *testing.B) {
	certificate, roots := testCertificate(b, "127.0.0.1")
	listener, err := quicgo.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{quicALPN},
	}, &quicgo.Config{EnableDatagrams: true})
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	clientDone := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		server, acceptErr := AcceptQUIC(connection)
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer server.Close()
		for range b.N {
			packet, receiveErr := server.Receive(context.Background())
			if receiveErr != nil {
				serverResult <- receiveErr
				return
			}
			if sendErr := server.Send(context.Background(), packet); sendErr != nil {
				serverResult <- sendErr
				return
			}
		}
		<-clientDone
		serverResult <- nil
	}()
	client, err := DialQUIC(context.Background(), QUICConfig{
		Address:    listener.Addr().String(),
		ServerName: "127.0.0.1",
		RootCAs:    roots,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	payload := bytes.Repeat([]byte{1}, 4_096)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := client.Send(context.Background(), payload); err != nil {
			b.Fatal(err)
		}
		received, err := client.Receive(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		if len(received) != len(payload) {
			b.Fatalf("unexpected payload size: %d", len(received))
		}
	}
	b.StopTimer()
	close(clientDone)
	if err := <-serverResult; err != nil {
		b.Fatal(err)
	}
}
