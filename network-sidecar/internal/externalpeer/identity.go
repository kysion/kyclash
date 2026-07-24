package externalpeer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

var ErrInvalidIdentity = errors.New("invalid external-peer identity")

type ClientDescriptorConfig struct {
	RunID              string
	ExpiresAt          time.Time
	VirtualMacModel    string
	PlatformUUID       string
	ClientIPv4         netip.Addr
	ClientMAC          string
	WireGuardPublicKey []byte
}

type PeerDescriptorConfig struct {
	RunID                    string
	IssuedAt                 time.Time
	ExpiresAt                time.Time
	ClientPlatformUUID       string
	PeerPlatformUUID         string
	ClientIPv4               netip.Addr
	PeerIPv4                 netip.Addr
	ClientMAC                string
	PeerMAC                  string
	ClientWireGuardPublicKey []byte
	ClientOverlayPublicKey   []byte
	Endpoints                []profile.Endpoint
	SystemSSHHostPublicKey   []byte
}

func NewClientIdentity(runID string) (*ClientIdentity, error) {
	if !validRunID(runID) {
		return nil, ErrInvalidIdentity
	}
	tlsPublic, tlsPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: clientCertificateIdentity(runID),
		},
		SignatureAlgorithm: x509.PureEd25519,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, tlsPrivate)
	if err != nil {
		clear(tlsPrivate)
		return nil, err
	}
	overlayPublic, overlayPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		clear(tlsPrivate)
		clear(csrDER)
		return nil, err
	}
	overlaySSH, err := ssh.NewPublicKey(overlayPublic)
	if err != nil {
		clear(tlsPrivate)
		clear(csrDER)
		clear(overlayPrivate)
		return nil, err
	}
	identity := &ClientIdentity{
		TLSPrivateKey:     tlsPrivate,
		TLSCSRDER:         csrDER,
		OverlayPrivateKey: overlayPrivate,
		OverlayPublicKey:  overlaySSH.Marshal(),
	}
	_ = tlsPublic
	return identity, nil
}

func (identity *ClientIdentity) PublicArtifacts(
	config ClientDescriptorConfig,
) (ClientPublicDescriptor, ClientPublicArtifacts, error) {
	if identity == nil ||
		len(identity.TLSPrivateKey) != ed25519.PrivateKeySize ||
		len(identity.TLSCSRDER) == 0 ||
		len(identity.OverlayPublicKey) == 0 {
		return ClientPublicDescriptor{}, ClientPublicArtifacts{}, ErrInvalidIdentity
	}
	csrPublicHash, err := validateClientCSR(identity.TLSCSRDER, config.RunID)
	if err != nil {
		return ClientPublicDescriptor{}, ClientPublicArtifacts{}, err
	}
	overlayKey, err := ssh.ParsePublicKey(identity.OverlayPublicKey)
	if err != nil || overlayKey.Type() != ssh.KeyAlgoED25519 {
		return ClientPublicDescriptor{}, ClientPublicArtifacts{}, ErrInvalidIdentity
	}
	value := ClientPublicDescriptor{
		SchemaVersion:                        SchemaVersion,
		RunID:                                config.RunID,
		ExpiresAt:                            config.ExpiresAt.Unix(),
		VMName:                               ClientVMName,
		VirtualMacModel:                      config.VirtualMacModel,
		PlatformUUID:                         config.PlatformUUID,
		En0PrivateIPv4:                       config.ClientIPv4.String(),
		En0MAC:                               config.ClientMAC,
		WireGuardPublicKey:                   base64.StdEncoding.EncodeToString(config.WireGuardPublicKey),
		TLSClientCSRDER_SHA256:               HashHex(identity.TLSCSRDER),
		TLSClientPublicKeySHA256:             csrPublicHash,
		OverlaySSHClientPublicKeySHA256:      HashHex(identity.OverlayPublicKey),
		OverlaySSHClientPublicKeyFingerprint: ssh.FingerprintSHA256(overlayKey),
	}
	encoded, err := EncodeClientPublicDescriptor(value)
	if err != nil {
		return ClientPublicDescriptor{}, ClientPublicArtifacts{}, err
	}
	return value, ClientPublicArtifacts{
		Descriptor:             encoded,
		TLSClientCSRDER:        append([]byte(nil), identity.TLSCSRDER...),
		OverlayClientPublicKey: append([]byte(nil), identity.OverlayPublicKey...),
	}, nil
}

func (identity *ClientIdentity) TLSCertificate(clientCertificateDER []byte) (tls.Certificate, error) {
	if identity == nil ||
		len(identity.TLSPrivateKey) != ed25519.PrivateKeySize ||
		len(clientCertificateDER) == 0 {
		return tls.Certificate{}, ErrInvalidIdentity
	}
	certificate, err := x509.ParseCertificate(clientCertificateDER)
	if err != nil {
		return tls.Certificate{}, ErrInvalidIdentity
	}
	public := identity.TLSPrivateKey.Public().(ed25519.PublicKey)
	certificatePublic, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, certificatePublic) {
		return tls.Certificate{}, ErrInvalidIdentity
	}
	return tls.Certificate{
		Certificate: [][]byte{append([]byte(nil), clientCertificateDER...)},
		PrivateKey:  identity.TLSPrivateKey,
		Leaf:        certificate,
	}, nil
}

func NewPeerIdentity(
	now time.Time,
	expiresAt time.Time,
	runID string,
	peerIPv4 netip.Addr,
	clientCSRDER []byte,
) (*PeerIdentity, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !validRunID(runID) ||
		!validPrivateAddr(peerIPv4) ||
		innerPrefix().Contains(peerIPv4) ||
		!expiresAt.After(now.Add(MinRemainingLife)) ||
		expiresAt.After(now.Add(MaxRunLifetime)) {
		return nil, ErrInvalidIdentity
	}
	csr, err := x509.ParseCertificateRequest(clientCSRDER)
	if err != nil ||
		csr.CheckSignature() != nil ||
		csr.Subject.CommonName != clientCertificateIdentity(runID) ||
		len(csr.DNSNames) != 0 ||
		len(csr.EmailAddresses) != 0 ||
		len(csr.IPAddresses) != 0 ||
		len(csr.URIs) != 0 {
		return nil, ErrInvalidIdentity
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, ErrInvalidIdentity
	}

	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(caPrivate)
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	overlayPublic, overlayPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		clear(serverPrivate)
		return nil, err
	}
	wireGuardPrivate := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(wireGuardPrivate); err != nil {
		clear(serverPrivate)
		clear(overlayPrivate)
		return nil, err
	}
	wireGuardPublic, err := curve25519.X25519(wireGuardPrivate, curve25519.Basepoint)
	if err != nil {
		clear(serverPrivate)
		clear(overlayPrivate)
		clear(wireGuardPrivate)
		return nil, err
	}
	runNonce := make([]byte, 32)
	if _, err := rand.Read(runNonce); err != nil {
		clear(serverPrivate)
		clear(overlayPrivate)
		clear(wireGuardPrivate)
		clear(wireGuardPublic)
		return nil, err
	}

	notBefore := now.Add(-30 * time.Second).Truncate(time.Second)
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "KyClash external-peer run CA " + runID},
		NotBefore:             notBefore,
		NotAfter:              expiresAt.Truncate(time.Second),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.PureEd25519,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		clear(serverPrivate)
		clear(overlayPrivate)
		clear(wireGuardPrivate)
		clear(wireGuardPublic)
		clear(runNonce)
		return nil, err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "KyClash external-peer server " + runID},
		NotBefore:             notBefore,
		NotAfter:              expiresAt.Truncate(time.Second),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IP(peerIPv4.AsSlice())},
		SignatureAlgorithm:    x509.PureEd25519,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, serverPublic, caPrivate)
	if err != nil {
		clear(serverPrivate)
		clear(overlayPrivate)
		clear(wireGuardPrivate)
		clear(wireGuardPublic)
		clear(runNonce)
		clear(caDER)
		return nil, err
	}
	clientTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: clientCertificateIdentity(runID)},
		NotBefore:             notBefore,
		NotAfter:              expiresAt.Truncate(time.Second),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.PureEd25519,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, csr.PublicKey, caPrivate)
	if err != nil {
		clear(serverPrivate)
		clear(overlayPrivate)
		clear(wireGuardPrivate)
		clear(wireGuardPublic)
		clear(runNonce)
		clear(caDER)
		clear(serverDER)
		return nil, err
	}
	serverLeaf, err := x509.ParseCertificate(serverDER)
	if err != nil {
		clear(serverPrivate)
		clear(overlayPrivate)
		clear(wireGuardPrivate)
		clear(wireGuardPublic)
		clear(runNonce)
		clear(caDER)
		clear(serverDER)
		clear(clientDER)
		return nil, ErrInvalidIdentity
	}
	overlayKey, err := ssh.NewPublicKey(overlayPublic)
	if err != nil {
		clear(serverPrivate)
		clear(overlayPrivate)
		clear(wireGuardPrivate)
		clear(wireGuardPublic)
		clear(runNonce)
		clear(caDER)
		clear(serverDER)
		clear(clientDER)
		return nil, err
	}
	return &PeerIdentity{
		ServerTLSCertificate: tls.Certificate{
			Certificate: [][]byte{serverDER, caDER},
			PrivateKey:  serverPrivate,
			Leaf:        serverLeaf,
		},
		CADER:                caDER,
		ServerCertificateDER: serverDER,
		ClientCertificateDER: clientDER,
		OverlayPrivateKey:    overlayPrivate,
		OverlayPublicKey:     overlayKey.Marshal(),
		WireGuardPrivateKey:  wireGuardPrivate,
		WireGuardPublicKey:   wireGuardPublic,
		RunNonce:             runNonce,
	}, nil
}

func (identity *PeerIdentity) PublicArtifacts(
	config PeerDescriptorConfig,
	client ClientPublicDescriptor,
) (PeerPublicDescriptor, PeerPublicArtifacts, error) {
	if identity == nil ||
		len(identity.CADER) == 0 ||
		len(identity.ServerCertificateDER) == 0 ||
		len(identity.ClientCertificateDER) == 0 ||
		len(identity.OverlayPublicKey) == 0 ||
		len(identity.WireGuardPublicKey) != 32 ||
		len(identity.RunNonce) != 32 {
		return PeerPublicDescriptor{}, PeerPublicArtifacts{}, ErrInvalidIdentity
	}
	serverCertificate, err := x509.ParseCertificate(identity.ServerCertificateDER)
	if err != nil {
		return PeerPublicDescriptor{}, PeerPublicArtifacts{}, ErrInvalidIdentity
	}
	clientCertificate, err := x509.ParseCertificate(identity.ClientCertificateDER)
	if err != nil {
		return PeerPublicDescriptor{}, PeerPublicArtifacts{}, ErrInvalidIdentity
	}
	clientPublicDER, err := x509.MarshalPKIXPublicKey(clientCertificate.PublicKey)
	if err != nil {
		return PeerPublicDescriptor{}, PeerPublicArtifacts{}, ErrInvalidIdentity
	}
	overlayServer, err := ssh.ParsePublicKey(identity.OverlayPublicKey)
	if err != nil {
		return PeerPublicDescriptor{}, PeerPublicArtifacts{}, ErrInvalidIdentity
	}
	overlayClient, err := ssh.ParsePublicKey(config.ClientOverlayPublicKey)
	if err != nil ||
		HashHex(config.ClientOverlayPublicKey) != client.OverlaySSHClientPublicKeySHA256 ||
		ssh.FingerprintSHA256(overlayClient) != client.OverlaySSHClientPublicKeyFingerprint ||
		!equalBase64Key(client.WireGuardPublicKey, config.ClientWireGuardPublicKey) {
		return PeerPublicDescriptor{}, PeerPublicArtifacts{}, ErrInvalidIdentity
	}
	systemHost, err := ssh.ParsePublicKey(config.SystemSSHHostPublicKey)
	if err != nil || systemHost.Type() != ssh.KeyAlgoED25519 {
		return PeerPublicDescriptor{}, PeerPublicArtifacts{}, ErrInvalidIdentity
	}
	value := PeerPublicDescriptor{
		SchemaVersion: SchemaVersion,
		RunID:         config.RunID,
		IssuedAt:      config.IssuedAt.Unix(),
		ExpiresAt:     config.ExpiresAt.Unix(),

		ClientVMName:         ClientVMName,
		ClientPlatformUUID:   config.ClientPlatformUUID,
		PeerVMName:           PeerVMName,
		PeerPlatformUUID:     config.PeerPlatformUUID,
		BindInterface:        BindInterface,
		PeerEn0PrivateIPv4:   config.PeerIPv4.String(),
		ClientEn0PrivateIPv4: config.ClientIPv4.String(),
		ClientEn0MAC:         config.ClientMAC,
		PeerEn0MAC:           config.PeerMAC,
		Endpoints:            append([]profile.Endpoint(nil), config.Endpoints...),

		PeerWireGuardPublicKey:   base64.StdEncoding.EncodeToString(identity.WireGuardPublicKey),
		ClientWireGuardPublicKey: client.WireGuardPublicKey,
		PrivateEchoIPv4:          InnerPeerIPv4,
		PrivateEchoPort:          PrivateEchoPort,

		PublicCADER_SHA256:               HashHex(identity.CADER),
		ServerCertificateSHA256:          HashHex(identity.ServerCertificateDER),
		ServerCertificateIPSAN:           config.PeerIPv4.String(),
		ServerCertificateNotBefore:       serverCertificate.NotBefore.Unix(),
		ServerCertificateNotAfter:        serverCertificate.NotAfter.Unix(),
		ClientCertificateSHA256:          HashHex(identity.ClientCertificateDER),
		ClientCertificateIdentity:        clientCertificateIdentity(config.RunID),
		ClientCertificatePublicKeySHA256: HashHex(clientPublicDER),

		OverlaySSHAddress:                    net.JoinHostPort(InnerPeerIPv4, "22"),
		OverlaySSHServerPublicKeySHA256:      HashHex(identity.OverlayPublicKey),
		OverlaySSHServerPublicKeyFingerprint: ssh.FingerprintSHA256(overlayServer),
		OverlaySSHClientPublicKeySHA256:      client.OverlaySSHClientPublicKeySHA256,
		OverlaySSHClientPublicKeyFingerprint: ssh.FingerprintSHA256(overlayClient),
		RunNonceSHA256:                       HashHex(identity.RunNonce),

		SystemSSHProxyAddress:             net.JoinHostPort(InnerPeerIPv4, "2222"),
		SystemSSHProxyTarget:              "127.0.0.1:22",
		SystemSSHRestrictedAccount:        "kyclashlabssh",
		SystemSSHForcedCommand:            ForcedCommandName,
		SystemSSHHostPublicKeySHA256:      HashHex(config.SystemSSHHostPublicKey),
		SystemSSHHostPublicKeyFingerprint: ssh.FingerprintSHA256(systemHost),

		TransportOrder:  []profile.Transport{profile.QUIC, profile.WSS, profile.TCP},
		QUICALPN:        QUICALPN,
		WSSPath:         WSSPath,
		TLSVersion:      "1.3",
		MutualTLS:       true,
		InnerClientIPv4: InnerClientIPv4,
		InnerPeerIPv4:   InnerPeerIPv4,
	}
	encoded, err := EncodePeerPublicDescriptor(value)
	if err != nil {
		return PeerPublicDescriptor{}, PeerPublicArtifacts{}, err
	}
	return value, PeerPublicArtifacts{
		Descriptor:             encoded,
		CADER:                  append([]byte(nil), identity.CADER...),
		ServerCertificateDER:   append([]byte(nil), identity.ServerCertificateDER...),
		ClientCertificateDER:   append([]byte(nil), identity.ClientCertificateDER...),
		OverlayServerPublicKey: append([]byte(nil), identity.OverlayPublicKey...),
		SystemSSHHostPublicKey: append([]byte(nil), config.SystemSSHHostPublicKey...),
	}, nil
}

func ValidatePublicCertificateArtifacts(
	descriptor PeerPublicDescriptor,
	artifacts PeerPublicArtifacts,
	expected PeerExpectation,
) error {
	ca, err := x509.ParseCertificate(artifacts.CADER)
	if err != nil ||
		!ca.IsCA ||
		!ca.BasicConstraintsValid ||
		ca.Subject.String() != ca.Issuer.String() ||
		ca.CheckSignatureFrom(ca) != nil {
		return ErrInvalidArtifact
	}
	server, err := x509.ParseCertificate(artifacts.ServerCertificateDER)
	if err != nil ||
		server.IsCA ||
		!server.BasicConstraintsValid ||
		len(server.IPAddresses) != 1 ||
		!server.IPAddresses[0].Equal(expected.PeerIPv4.AsSlice()) ||
		len(server.DNSNames) != 0 ||
		len(server.EmailAddresses) != 0 ||
		len(server.URIs) != 0 ||
		!onlyExtKeyUsage(server, x509.ExtKeyUsageServerAuth) {
		return ErrInvalidArtifact
	}
	client, err := x509.ParseCertificate(artifacts.ClientCertificateDER)
	if err != nil ||
		client.IsCA ||
		!client.BasicConstraintsValid ||
		client.Subject.CommonName != clientCertificateIdentity(expected.RunID) ||
		len(client.IPAddresses) != 0 ||
		len(client.DNSNames) != 0 ||
		len(client.EmailAddresses) != 0 ||
		len(client.URIs) != 0 ||
		!onlyExtKeyUsage(client, x509.ExtKeyUsageClientAuth) {
		return ErrInvalidArtifact
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	now := expected.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if _, err := server.Verify(x509.VerifyOptions{
		Roots:       pool,
		DNSName:     expected.PeerIPv4.String(),
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return ErrInvalidArtifact
	}
	if _, err := client.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return ErrInvalidArtifact
	}
	csr, err := x509.ParseCertificateRequest(expected.ClientCSRDER)
	if err != nil || csr.CheckSignature() != nil {
		return ErrInvalidArtifact
	}
	csrPublic, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return ErrInvalidArtifact
	}
	clientPublic, err := x509.MarshalPKIXPublicKey(client.PublicKey)
	if err != nil || !bytes.Equal(csrPublic, clientPublic) {
		return ErrInvalidArtifact
	}
	if descriptor.ClientCertificatePublicKeySHA256 != HashHex(clientPublic) ||
		descriptor.ServerCertificateNotBefore != server.NotBefore.Unix() ||
		descriptor.ServerCertificateNotAfter != server.NotAfter.Unix() ||
		descriptor.ExpiresAt != server.NotAfter.Unix() ||
		descriptor.ExpiresAt != client.NotAfter.Unix() ||
		descriptor.ExpiresAt != ca.NotAfter.Unix() {
		return ErrInvalidArtifact
	}
	return nil
}

func validateClientCSR(data []byte, runID string) (string, error) {
	csr, err := x509.ParseCertificateRequest(data)
	if err != nil ||
		csr.CheckSignature() != nil ||
		csr.Subject.CommonName != clientCertificateIdentity(runID) ||
		len(csr.DNSNames) != 0 ||
		len(csr.EmailAddresses) != 0 ||
		len(csr.IPAddresses) != 0 ||
		len(csr.URIs) != 0 {
		return "", ErrInvalidIdentity
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return "", ErrInvalidIdentity
	}
	publicDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return "", ErrInvalidIdentity
	}
	return HashHex(publicDER), nil
}

func onlyExtKeyUsage(certificate *x509.Certificate, expected x509.ExtKeyUsage) bool {
	return certificate != nil &&
		len(certificate.ExtKeyUsage) == 1 &&
		certificate.ExtKeyUsage[0] == expected &&
		len(certificate.UnknownExtKeyUsage) == 0
}

func clientCertificateIdentity(runID string) string {
	return "net.kysion.kyclash.external-peer.client/" + runID
}

func randomSerial() *big.Int {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	raw[0] &= 0x7f
	return new(big.Int).SetBytes(raw[:])
}
