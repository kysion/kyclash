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

func TestTCPCarrierUsesMutualTLSWithExactTLS13(t *testing.T) {
	fixture := testMutualTLSCertificates(t, "sidecar.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{fixture.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    fixture.roots,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
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
		defer connection.Close()
		tlsConnection, ok := connection.(*tls.Conn)
		if !ok {
			serverResult <- errors.New("accepted connection is not TLS")
			return
		}
		if handshakeErr := tlsConnection.Handshake(); handshakeErr != nil {
			serverResult <- handshakeErr
			return
		}
		state := tlsConnection.ConnectionState()
		if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) != 1 ||
			state.PeerCertificates[0].Subject.CommonName != "kyclash-client.test" {
			serverResult <- errors.New("unexpected mutual TLS client identity")
			return
		}
		serverResult <- nil
	}()

	client, err := DialTCP(context.Background(), TCPConfig{
		Address:           listener.Addr().String(),
		ServerName:        "sidecar.test",
		RootCAs:           fixture.roots,
		ClientCertificate: &fixture.client,
		ExactTLS13:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestClientTLSOptionsAreOptInAndExactOnlyWhenRequested(t *testing.T) {
	fixture := testMutualTLSCertificates(t, "sidecar.test")
	ordinary := &tls.Config{MinVersion: tls.VersionTLS13}
	applyClientTLSOptions(ordinary, nil, false)
	if ordinary.MaxVersion != 0 || len(ordinary.Certificates) != 0 {
		t.Fatal("ordinary carrier unexpectedly enabled exact TLS or a client certificate")
	}

	mutual := &tls.Config{MinVersion: tls.VersionTLS13}
	applyClientTLSOptions(mutual, &fixture.client, false)
	if mutual.MaxVersion != 0 || len(mutual.Certificates) != 1 {
		t.Fatal("mutual TLS without exact-version policy changed the TLS maximum")
	}

	exact := &tls.Config{MinVersion: tls.VersionTLS13}
	applyClientTLSOptions(exact, &fixture.client, true)
	if exact.MaxVersion != tls.VersionTLS13 || len(exact.Certificates) != 1 {
		t.Fatal("exact mutual TLS policy was not applied")
	}
}

func TestTCPConfigFailsClosed(t *testing.T) {
	for _, config := range []TCPConfig{
		{},
		{Address: "example.test:443"},
		{Address: " example.test:443", ServerName: "example.test"},
		{Address: "example.test", ServerName: "example.test"},
		{Address: "example.test:443", ServerName: " example.test"},
		{Address: "example.test:443", ServerName: "example.test", Timeout: -1},
		{Address: "example.test:443", ServerName: "example.test", ClientCertificate: &tls.Certificate{}},
	} {
		if _, err := DialTCP(context.Background(), config); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("expected validation refusal for %#v, got %v", config, err)
		}
	}
}

type mutualTLSCertificates struct {
	server tls.Certificate
	client tls.Certificate
	roots  *x509.CertPool
}

func testMutualTLSCertificates(t testing.TB, serverName string) mutualTLSCertificates {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "KyClash carrier test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	server := testSignedCertificate(t, ca, caPrivate, serverName, true, big.NewInt(11))
	client := testSignedCertificate(t, ca, caPrivate, "kyclash-client.test", false, big.NewInt(12))
	return mutualTLSCertificates{server: server, client: client, roots: roots}
}

func testSignedCertificate(t testing.TB, ca *x509.Certificate, caPrivate ed25519.PrivateKey, identity string, server bool, serial *big.Int) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: identity},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if address := net.ParseIP(identity); address != nil {
			template.IPAddresses = []net.IP{address}
		} else {
			template.DNSNames = []string{identity}
		}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
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
