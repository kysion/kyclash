package carrier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestTCPCarrierAuthenticatesTLSAndExchangesPacket(t *testing.T) {
	certificate, roots := testCertificate(t, "sidecar.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		server := NewStream(connection)
		defer server.Close()
		packet, receiveErr := server.Receive(context.Background())
		if receiveErr != nil {
			serverResult <- receiveErr
			return
		}
		serverResult <- server.Send(context.Background(), packet)
	}()
	client, err := DialTCP(context.Background(), TCPConfig{
		Address:    listener.Addr().String(),
		ServerName: "sidecar.test",
		RootCAs:    roots,
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

func TestTCPCarrierRejectsWrongServerIdentity(t *testing.T) {
	certificate, roots := testCertificate(t, "sidecar.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			if tlsConnection, ok := connection.(*tls.Conn); ok {
				_ = tlsConnection.Handshake()
			}
			_ = connection.Close()
		}
		serverDone <- struct{}{}
	}()
	_, err = DialTCP(context.Background(), TCPConfig{
		Address:    listener.Addr().String(),
		ServerName: "attacker.test",
		RootCAs:    roots,
	})
	if err == nil {
		t.Fatal("expected server identity refusal")
	}
	<-serverDone
}

func TestTCPConfigFailsClosed(t *testing.T) {
	for _, config := range []TCPConfig{
		{},
		{Address: "example.test:443"},
		{Address: " example.test:443", ServerName: "example.test"},
		{Address: "example.test", ServerName: "example.test"},
		{Address: "example.test:443", ServerName: " example.test"},
		{Address: "example.test:443", ServerName: "example.test", Timeout: -1},
	} {
		if _, err := DialTCP(context.Background(), config); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("expected validation refusal for %#v, got %v", config, err)
		}
	}
}

func testCertificate(t testing.TB, serverName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if address := net.ParseIP(serverName); address != nil {
		template.IPAddresses = []net.IP{address}
	} else {
		template.DNSNames = []string{serverName}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}, pool
}
