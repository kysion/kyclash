package productionpeer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func TestSystemdCredentialLoaderRemainsFailClosedUntilInvocationBoundV2(t *testing.T) {
	config := validConfig(t)
	bundle, err := LoadSystemdCredentialBundle(config)
	if err != ErrCredentialUnavailable || bundle != nil {
		t.Fatalf("unimplemented live credential boundary became available: bundle=%v err=%v", bundle, err)
	}
}

func TestCredentialBundleMatchesSystemRootHostnameLocalHashAndWireGuardIdentity(t *testing.T) {
	config := validConfig(t)
	bundle, roots := validCredentialBundle(t, &config)
	defer bundle.Close()
	if err := validateCredentialBundle(config, bundle, roots); err != nil {
		t.Fatalf("valid fixed credential material was rejected: %v", err)
	}

	hashMismatch := config
	hashMismatch.TLS.LocalCertificateSHA256 =
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := validateCredentialBundle(hashMismatch, bundle, roots); err != ErrCredentialUnavailable {
		t.Fatalf("local certificate mismatch was not refused: %v", err)
	}

	untrustedRoots := x509.NewCertPool()
	if err := validateCredentialBundle(config, bundle, untrustedRoots); err != ErrCredentialUnavailable {
		t.Fatalf("certificate outside client system roots was not refused: %v", err)
	}

	otherPrivate := bytes.Repeat([]byte{0x66}, curve25519.ScalarSize)
	otherEncoded := make([]byte, base64.StdEncoding.EncodedLen(len(otherPrivate)))
	base64.StdEncoding.Encode(otherEncoded, otherPrivate)
	originalPrivate := bundle.wireGuardPrivateKey
	bundle.wireGuardPrivateKey = otherEncoded
	if err := validateCredentialBundle(config, bundle, roots); err != ErrCredentialUnavailable {
		t.Fatalf("WireGuard private/public mismatch was not refused: %v", err)
	}
	clear(bundle.wireGuardPrivateKey)
	bundle.wireGuardPrivateKey = originalPrivate
	clear(otherPrivate)
}

func TestCredentialBundleNeverFormatsOrRetainsSecretBytesAfterClose(t *testing.T) {
	config := validConfig(t)
	bundle, _ := validCredentialBundle(t, &config)
	withOwnedSlack := func(encoded []byte) []byte {
		owned := make([]byte, len(encoded), len(encoded)+16)
		copy(owned, encoded)
		clear(encoded)
		for index := len(owned); index < cap(owned); index++ {
			owned[:cap(owned)][index] = 0xa5
		}
		return owned
	}
	bundle.tlsCertificatePEM = withOwnedSlack(bundle.tlsCertificatePEM)
	bundle.tlsPrivateKeyPEM = withOwnedSlack(bundle.tlsPrivateKeyPEM)
	bundle.wireGuardPrivateKey = withOwnedSlack(bundle.wireGuardPrivateKey)
	certificateBytes := bundle.tlsCertificatePEM[:cap(bundle.tlsCertificatePEM)]
	privateKeyBytes := bundle.tlsPrivateKeyPEM[:cap(bundle.tlsPrivateKeyPEM)]
	wireGuardBytes := bundle.wireGuardPrivateKey[:cap(bundle.wireGuardPrivateKey)]
	copiedValue := *bundle
	for _, formatted := range []string{
		bundle.String(),
		fmt.Sprintf("%v", bundle),
		fmt.Sprintf("%+v", bundle),
		fmt.Sprintf("%#v", bundle),
		fmt.Sprintf("%s", bundle),
		fmt.Sprintf("%q", bundle),
		fmt.Sprintf("%v", copiedValue),
		fmt.Sprintf("%+v", copiedValue),
		fmt.Sprintf("%#v", copiedValue),
		fmt.Sprintf("%s", copiedValue),
		fmt.Sprintf("%q", copiedValue),
	} {
		for _, forbidden := range []string{
			string(privateKeyBytes),
			string(wireGuardBytes),
			config.WireGuard.ServerPublicKeyBase64,
		} {
			if strings.Contains(formatted, forbidden) {
				t.Fatal("credential formatting exposed identity material")
			}
		}
		if !strings.Contains(formatted, "<redacted>") {
			t.Fatal("credential formatting lost its fixed redaction marker")
		}
	}
	bundle.Close()
	for name, encoded := range map[string][]byte{
		"certificate": certificateBytes,
		"tls-key":     privateKeyBytes,
		"wireguard":   wireGuardBytes,
	} {
		for _, value := range encoded {
			if value != 0 {
				t.Fatalf("%s credential was not cleared", name)
			}
		}
	}
}

func validCredentialBundle(t *testing.T, config *Config) (*CredentialBundle, *x509.CertPool) {
	t.Helper()
	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "KyClash test root"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: config.TLS.ServerName},
		DNSNames:     []string{config.TLS.ServerName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, leafPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...,
	)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})

	wireGuardPrivate := bytes.Repeat([]byte{0x44}, curve25519.ScalarSize)
	wireGuardPublic, err := curve25519.X25519(wireGuardPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	config.WireGuard.ServerPublicKeyBase64 = base64.StdEncoding.EncodeToString(wireGuardPublic)
	leafHash := sha256.Sum256(leafDER)
	config.TLS.LocalCertificateSHA256 = hex.EncodeToString(leafHash[:])
	if err := config.Validate(); err != nil {
		t.Fatalf("generated public identity did not satisfy config: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	bundle := &CredentialBundle{
		tlsCertificatePEM:   certificatePEM,
		tlsPrivateKeyPEM:    privatePEM,
		wireGuardPrivateKey: []byte(base64.StdEncoding.EncodeToString(wireGuardPrivate)),
	}
	clear(wireGuardPrivate)
	clear(wireGuardPublic)
	clear(privateDER)
	return bundle, roots
}
