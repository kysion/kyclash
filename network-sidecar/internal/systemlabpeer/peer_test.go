package systemlabpeer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/userspace"
	"golang.org/x/crypto/curve25519"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPeerPublishesStrictDualStackDescriptorAndCleansItOnClose(t *testing.T) {
	root := privateTempDir(t)
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clientKey := bytes.Repeat([]byte{0x42}, 32)
	clientPath := filepath.Join(root, "client.key")
	if err := os.WriteFile(clientPath, clientKey, 0o600); err != nil {
		t.Fatal(err)
	}
	descriptorPath := filepath.Join(root, "public", "descriptor.json")
	peer, err := Start(context.Background(), Config{
		RunID:               "0123456789abcdef",
		ClientPublicKeyPath: clientPath,
		PrivateDir:          privateDir,
		DescriptorPath:      descriptorPath,
		ExpiresAt:           time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.WaitReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	descriptor := peer.Descriptor()
	if descriptor.RunID != "0123456789abcdef" || len(descriptor.Endpoints) != 3 || len(descriptor.EchoAddresses) != 2 {
		t.Fatalf("unexpected descriptor: %#v", descriptor)
	}
	if descriptor.EchoAddresses[0] != "10.88.0.2:8080" || descriptor.EchoAddresses[1] != "[fd00:88::2]:8080" {
		t.Fatalf("dual-stack echo addresses = %#v", descriptor.EchoAddresses)
	}
	for _, endpoint := range descriptor.Endpoints {
		if endpoint.URL == "" || endpoint.Transport == "" {
			t.Fatalf("invalid endpoint: %#v", endpoint)
		}
	}
	data, err := os.ReadFile(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Descriptor
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		t.Fatal("descriptor has an unexpected second JSON value")
	}
	// The descriptor intentionally carries the public key as base64 text.
	if decoded.ClientPublicKey == "" {
		t.Fatal("descriptor omitted client public key")
	}
	manifest, err := readManifest(filepath.Join(privateDir, manifestFile))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Ports.QUIC == 0 || manifest.Ports.WSS == 0 || manifest.Ports.TCP == 0 {
		t.Fatalf("manifest ports were not persisted: %#v", manifest.Ports)
	}
	if hash := sha256.Sum256(clientKey); manifest.ClientKeySHA256 != hexEncode(hash[:]) {
		t.Fatal("manifest client key hash mismatch")
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-peer.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("peer did not finish cleanup")
	}
	if _, err := os.Lstat(descriptorPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descriptor survived exact cleanup: %v", err)
	}
}

func TestPeerRejectsUnsafeInputAndExistingDescriptor(t *testing.T) {
	root := privateTempDir(t)
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(root, "client.key")
	if err := os.WriteFile(clientPath, bytes.Repeat([]byte{0x11}, 31), 0o600); err != nil {
		t.Fatal(err)
	}
	config := Config{RunID: "0123456789abcdef", ClientPublicKeyPath: clientPath, PrivateDir: privateDir, DescriptorPath: filepath.Join(root, "descriptor.json")}
	if _, err := Start(context.Background(), config); !errors.Is(err, ErrInvalidConfig) && !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("short client key error = %v", err)
	}
	if err := os.WriteFile(clientPath, bytes.Repeat([]byte{0x11}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(clientPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(context.Background(), config); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("world-readable client key error = %v", err)
	}
	if err := os.Chmod(clientPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.DescriptorPath, []byte("occupied"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(context.Background(), config); !errors.Is(err, ErrExistingDescriptor) {
		t.Fatalf("existing descriptor error = %v", err)
	}
}

func TestPeerReopensExactPersistedIdentityAndPorts(t *testing.T) {
	root := privateTempDir(t)
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(root, "client.key")
	if err := os.WriteFile(clientPath, bytes.Repeat([]byte{0x2a}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	config := Config{RunID: "8899aabbccddeeff", ClientPublicKeyPath: clientPath, PrivateDir: privateDir, DescriptorPath: filepath.Join(root, "descriptor.json"), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	first, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	firstDescriptor := first.Descriptor()
	firstManifest, err := readManifest(filepath.Join(privateDir, manifestFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("first peer did not close")
	}
	second, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer closePeerAndWait(t, second)
	secondDescriptor := second.Descriptor()
	secondManifest, err := readManifest(filepath.Join(privateDir, manifestFile))
	if err != nil {
		t.Fatal(err)
	}
	if firstDescriptor.PeerPublicKey != secondDescriptor.PeerPublicKey || firstDescriptor.CertificateSHA256 != secondDescriptor.CertificateSHA256 || firstDescriptor.Endpoints[0].URL != secondDescriptor.Endpoints[0].URL || firstDescriptor.Endpoints[1].URL != secondDescriptor.Endpoints[1].URL || firstDescriptor.Endpoints[2].URL != secondDescriptor.Endpoints[2].URL {
		t.Fatal("persisted peer identity or ports changed across restart")
	}
	if firstManifest.Ports != secondManifest.Ports || firstManifest.RootCertificateSHA256 != secondManifest.RootCertificateSHA256 {
		t.Fatal("persisted manifest changed across restart")
	}
}

func TestPeerAcceptsGuestTrustFixtureRootLeafAndKey(t *testing.T) {
	root := privateTempDir(t)
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(root, "client.key")
	if err := os.WriteFile(clientPath, bytes.Repeat([]byte{0x31}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "fixture root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "127.0.0.1"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(privateDir, "loopback-trust-root.pem")
	leafPath := filepath.Join(privateDir, "loopback-leaf.pem")
	keyPath := filepath.Join(privateDir, "loopback-leaf.key")
	if err := os.WriteFile(rootPath, pemEncodeCertificate(rootDER), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafPath, pemEncodeCertificate(leafDER), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	parsedRoot, err := parsePEMCertificate(pemEncodeCertificate(rootDER))
	if err != nil {
		t.Fatalf("parse fixture root: %v", err)
	}
	parsedLeaf, err := parsePEMCertificate(pemEncodeCertificate(leafDER))
	if err != nil {
		t.Fatalf("parse fixture leaf: %v", err)
	}
	if err := validateCertificateChain(parsedRoot, parsedLeaf); err != nil {
		t.Fatalf("validate fixture chain: %v", err)
	}
	parsedKey, err := parseTLSPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil || !privateKeyMatchesCertificate(parsedKey, parsedLeaf) {
		t.Fatalf("validate fixture key: %v", err)
	}
	peer, err := Start(context.Background(), Config{RunID: "1234567890abcdef", ClientPublicKeyPath: clientPath, PrivateDir: privateDir, DescriptorPath: filepath.Join(root, "descriptor.json"), RootCertificatePath: rootPath, CertificatePath: leafPath, TLSPrivateKeyPath: keyPath, ExpiresAt: time.Now().UTC().Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	defer closePeerAndWait(t, peer)
	if peer.Descriptor().CertificatePath != leafPath || peer.Descriptor().CertificateSHA256 != hashHex(leafDER) {
		t.Fatal("fixture leaf identity was not preserved")
	}
}

func TestCertificateChainRejectsLeafOutlivingRoot(t *testing.T) {
	now := time.Now().UTC()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(201),
		Subject:               pkix.Name{CommonName: "short root"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(202),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(2 * time.Hour),
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCertificateChain(rootDER, leafDER); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("leaf outliving root was accepted: %v", err)
	}
}

func hexEncode(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = alphabet[item>>4]
		result[index*2+1] = alphabet[item&0xf]
	}
	return string(result)
}

func TestValidateDescriptorRejectsNonLoopbackAndUnknownTransport(t *testing.T) {
	base := Descriptor{
		SchemaVersion:   descriptorVersion,
		RunID:           "0123456789abcdef",
		PeerPublicKey:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ClientPublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		Endpoints: []profile.Endpoint{
			{Transport: profile.QUIC, URL: "https://127.0.0.1:20001"},
			{Transport: profile.WSS, URL: "wss://127.0.0.1:20002/kynp"},
			{Transport: profile.TCP, URL: "tcp://127.0.0.1:20003"},
		},
		EchoAddresses:     []string{"10.88.0.2:8080", "[fd00:88::2]:8080"},
		CertificateSHA256: strings.Repeat("a", 64),
		CertificatePath:   "/var/tmp/cert.der",
		ExpiresAt:         time.Now().Add(time.Hour).Unix(),
	}
	if err := validateDescriptor(base); err != nil {
		t.Fatal(err)
	}
	base.Endpoints[0].URL = "https://example.test:20001"
	if err := validateDescriptor(base); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("non-loopback endpoint error = %v", err)
	}
}

func TestPeerDrainsHijackedWSSConnectionsBeforeDone(t *testing.T) {
	root := privateTempDir(t)
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(root, "client.key")
	if err := os.WriteFile(clientPath, bytes.Repeat([]byte{0x66}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	peer, err := Start(context.Background(), Config{RunID: "aabbccddeeff0011", ClientPublicKeyPath: clientPath, PrivateDir: privateDir, DescriptorPath: filepath.Join(root, "descriptor.json"), ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := peer.Descriptor()
	manifest, err := readManifest(filepath.Join(privateDir, manifestFile))
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	rootDER, err := parsePEMCertificate(mustReadFile(t, filepath.Join(privateDir, manifest.RootCertificateFile)))
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	roots.AddCert(rootCertificate)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var connections []*websocket.Conn
	for range 2 {
		connection, _, dialErr := websocket.Dial(ctx, descriptor.Endpoints[1].URL, &websocket.DialOptions{HTTPClient: client, CompressionMode: websocket.CompressionDisabled})
		if dialErr != nil {
			_ = peer.Close()
			t.Fatal(dialErr)
		}
		connections = append(connections, connection)
	}
	deadline := time.Now().Add(2 * time.Second)
	registered, handlers, registrations := 0, 0, 0
	for time.Now().Before(deadline) {
		registered, handlers, registrations = peer.wssConnections.counts()
		if registrations >= len(connections) && handlers == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	registered, _, registrations = peer.wssConnections.counts()
	if registrations < len(connections) {
		_ = peer.Close()
		t.Fatalf("hijacked connections were not registered: got %d want %d", registered, len(connections))
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-peer.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Peer.Done retained a hijacked WSS connection")
	}
	registered, handlers, _ = peer.wssConnections.counts()
	if registered != 0 || handlers != 0 {
		t.Fatalf("WSS lifecycle registry retained state: connections=%d handlers=%d", registered, handlers)
	}
	for _, connection := range connections {
		_ = connection.Close(websocket.StatusNormalClosure, "test complete")
	}
}

func TestPeerBoundsStalledTCPHandshakeAndAcceptsNextConnection(t *testing.T) {
	root := privateTempDir(t)
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(root, "client.key")
	if err := os.WriteFile(clientPath, bytes.Repeat([]byte{0x77}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	peer, err := Start(context.Background(), Config{RunID: "1122334455667788", ClientPublicKeyPath: clientPath, PrivateDir: privateDir, DescriptorPath: filepath.Join(root, "descriptor.json"), ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	defer closePeerAndWait(t, peer)
	descriptor := peer.Descriptor()
	manifest, err := readManifest(filepath.Join(privateDir, manifestFile))
	if err != nil {
		t.Fatal(err)
	}
	rootDER, err := parsePEMCertificate(mustReadFile(t, filepath.Join(privateDir, manifest.RootCertificateFile)))
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCertificate)
	tcpURL, err := url.Parse(descriptor.Endpoints[2].URL)
	if err != nil {
		t.Fatal(err)
	}
	stalled, err := net.Dial("tcp", tcpURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := stalled.SetReadDeadline(time.Now().Add(tlsHandshakeLimit + time.Second)); err != nil {
		_ = stalled.Close()
		t.Fatal(err)
	}
	var one [1]byte
	_, readErr := stalled.Read(one[:])
	_ = stalled.Close()
	if readErr == nil || time.Since(start) > tlsHandshakeLimit+2*time.Second {
		t.Fatalf("stalled TLS handshake was not bounded: err=%v elapsed=%s", readErr, time.Since(start))
	}
	accepted, err := tls.Dial("tcp", tcpURL.Host, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("TCP listener did not recover after stalled handshake: %v", err)
	}
	chain := accepted.ConnectionState().PeerCertificates
	if len(chain) != 2 || hashHex(chain[0].Raw) != descriptor.CertificateSHA256 || hashHex(chain[1].Raw) != manifest.RootCertificateSHA256 {
		_ = accepted.Close()
		t.Fatal("recovered TCP connection did not carry the expected chain")
	}
	if err := accepted.Close(); err != nil {
		t.Fatal(err)
	}
	waitPeerInactive(t, peer)
}

const (
	systemLabCarrierProofTimeout = 20 * time.Second
	systemLabStopTimeout         = 5 * time.Second
	systemLabCleanupTimeout      = 5 * time.Second
)

func TestPeerServesUserspaceHealthOnAllThreeLoopbackCarriers(t *testing.T) {
	root := privateTempDir(t)
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clientPrivate := bytes.Repeat([]byte{0x71}, 32)
	clientPublic, err := curve25519.X25519(clientPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(root, "client.key")
	if err := os.WriteFile(clientPath, clientPublic, 0o600); err != nil {
		t.Fatal(err)
	}
	peer, err := Start(context.Background(), Config{
		RunID:               "fedcba9876543210",
		ClientPublicKeyPath: clientPath,
		PrivateDir:          privateDir,
		DescriptorPath:      filepath.Join(root, "descriptor.json"),
		ExpiresAt:           time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closePeerAndWait(t, peer)
	descriptor := peer.Descriptor()
	manifest, err := readManifest(filepath.Join(privateDir, manifestFile))
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(privateDir, manifest.RootCertificateFile))
	if err != nil {
		t.Fatal(err)
	}
	rootDER, err := parsePEMCertificate(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := os.ReadFile(descriptor.CertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	certificateDER, err := parsePEMCertificate(certificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCertificate)
	if rootCertificate.Equal(certificate) {
		t.Fatal("test trust pool unexpectedly uses the leaf as its root")
	}
	client, err := userspace.NewLab(clientPrivate, roots, netip.MustParseAddrPort("10.88.0.2:8080"), "system-lab-peer-test")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	networkProfile := &profile.Profile{
		SchemaVersion: profile.SchemaVersion,
		ProfileID:     "system-lab-peer-test",
		ControlPlane:  "https://127.0.0.1/control",
		IdentityRef:   "keychain:kyclash.system.lab.test",
		Site:          profile.Site{ID: "system-lab", DisplayName: "system lab", PrivateCIDRs: []string{"10.88.0.2/32", "fd00:88::2/128"}},
		Tunnel:        profile.Tunnel{LocalAddresses: []string{"10.88.0.1/32", "fd00:88::1/128"}, PeerPublicKey: descriptor.PeerPublicKey, KeepaliveSeconds: 5},
		Transports:    profile.Transports{Primary: profile.QUIC, Fallbacks: []profile.Transport{profile.WSS, profile.TCP}, Endpoints: descriptor.Endpoints},
		Policy:        profile.Policy{ConnectTimeoutSeconds: 5, HealthIntervalSeconds: 1, FallbackThreshold: 1},
	}
	if err := networkProfile.Validate(); err != nil {
		t.Fatal(err)
	}
	tcpEndpoint, err := networkProfile.Endpoint(profile.TCP)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := tls.Dial("tcp", tcpEndpoint.Address, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: tcpEndpoint.ServerName})
	if err != nil {
		t.Fatalf("root-trusted TCP handshake: %v", err)
	}
	chain := serverTLS.ConnectionState().PeerCertificates
	if len(chain) != 2 {
		_ = serverTLS.Close()
		t.Fatalf("server did not present leaf+root chain: %d certificates", len(chain))
	}
	if hashHex(chain[0].Raw) != descriptor.CertificateSHA256 || hashHex(chain[1].Raw) != manifest.RootCertificateSHA256 {
		_ = serverTLS.Close()
		t.Fatalf("server chain fingerprints mismatch: leaf=%s root=%s", hashHex(chain[0].Raw), hashHex(chain[1].Raw))
	}
	if err := serverTLS.Close(); err != nil {
		t.Fatal(err)
	}
	waitPeerInactive(t, peer)
	if _, err := client.Prepare(context.Background(), networkProfile, "system-lab-peer-test"); err != nil {
		t.Fatal(err)
	}
	var previous *trackedCarrier
	for _, transport := range []profile.Transport{profile.QUIC, profile.WSS, profile.TCP} {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), systemLabCarrierProofTimeout)
			defer cancel()
			if previous != nil {
				select {
				case <-previous.closed:
				default:
					t.Fatalf("break-before-make violated: previous carrier was not closed before %s", transport)
				}
				peer.mu.Lock()
				inactive := peer.active == nil && !peer.deviceUp
				peer.mu.Unlock()
				if !inactive {
					t.Fatalf("break-before-make violated: peer still active before %s", transport)
				}
			}
			endpoint, err := networkProfile.Endpoint(transport)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Connect(ctx, transport, endpoint); err != nil {
				t.Fatalf("%s connect: %v", transport, err)
			}
			active := false
			var attached *trackedCarrier
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				peer.mu.Lock()
				attached = peer.active
				active = attached != nil
				peer.mu.Unlock()
				if active {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !active {
				select {
				case attachErr := <-peer.attachErrors:
					t.Fatalf("%s carrier was not attached by peer: %v", transport, attachErr)
				case detachErr := <-peer.detachReasons:
					t.Fatalf("%s carrier detached immediately: %v", transport, detachErr)
				default:
					t.Fatalf("%s carrier was not attached by peer", transport)
				}
			}
			connection, err := client.DialLabTCP(ctx, netip.MustParseAddrPort("10.88.0.2:8080"))
			if err != nil {
				t.Fatalf("%s IPv4 echo dial: %v", transport, err)
			}
			if _, err := connection.Write([]byte("v4")); err != nil {
				_ = connection.Close()
				t.Fatalf("%s IPv4 echo write: %v", transport, err)
			}
			response := make([]byte, 2)
			if _, err := io.ReadFull(connection, response); err != nil || string(response) != "v4" {
				_ = connection.Close()
				t.Fatalf("%s IPv4 echo response: %q %v", transport, response, err)
			}
			_ = connection.Close()
			connection, err = client.DialLabTCP(ctx, netip.MustParseAddrPort("[fd00:88::2]:8080"))
			if err != nil {
				t.Fatalf("%s IPv6 echo dial: %v", transport, err)
			}
			if _, err := connection.Write([]byte("v6")); err != nil {
				_ = connection.Close()
				t.Fatalf("%s IPv6 echo write: %v", transport, err)
			}
			response = make([]byte, 2)
			if _, err := io.ReadFull(connection, response); err != nil || string(response) != "v6" {
				_ = connection.Close()
				t.Fatalf("%s IPv6 echo response: %q %v", transport, response, err)
			}
			_ = connection.Close()
			health, err := client.Health(ctx)
			if err != nil || !health.Reachable || health.LossPercent != 0 {
				t.Fatalf("%s health: %#v %v", transport, health, err)
			}
			if err := client.Disconnect(ctx); err != nil {
				t.Fatalf("%s disconnect: %v", transport, err)
			}
			if attached == nil {
				t.Fatalf("%s had no carrier to close", transport)
			}
			select {
			case <-attached.closed:
			case <-time.After(3 * time.Second):
				t.Fatalf("%s carrier did not close before next transport", transport)
			}
			waitPeerInactive(t, peer)
			previous = attached
		}()
	}
	func() {
		ctx, cancel := context.WithTimeout(context.Background(), systemLabStopTimeout)
		defer cancel()
		if err := client.Stop(ctx); err != nil {
			t.Fatal(err)
		}
	}()
}

func closePeerAndWait(t *testing.T, peer *Peer) {
	t.Helper()
	if err := peer.Close(); err != nil {
		t.Errorf("close peer: %v", err)
		return
	}
	timer := time.NewTimer(systemLabCleanupTimeout)
	defer timer.Stop()
	select {
	case err := <-peer.Done():
		if err != nil {
			t.Errorf("peer cleanup: %v", err)
		}
	case <-timer.C:
		t.Error("peer did not finish cleanup")
	}
}

func waitPeerInactive(t *testing.T, peer *Peer) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		peer.mu.Lock()
		inactive := peer.active == nil && !peer.deviceUp
		peer.mu.Unlock()
		if inactive {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("peer retained an active carrier after close")
}
