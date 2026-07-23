package productionpeer

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

const (
	MaxTLSCertificateCredentialSize   = 256 * 1024
	MaxTLSPrivateKeyCredentialSize    = 64 * 1024
	MaxWireGuardPrivateCredentialSize = 128
)

var ErrCredentialUnavailable = errors.New("production peer credential unavailable")

// CredentialBundle owns the exact bytes read from the fixed systemd
// credential directory. It deliberately exposes neither JSON fields nor a
// printable representation of private material. Call Close as soon as the
// future live IdentityProvider has constructed its runtime keys.
type CredentialBundle struct {
	tlsCertificatePEM   []byte
	tlsPrivateKeyPEM    []byte
	wireGuardPrivateKey []byte
}

const credentialBundleRedacted = "CredentialBundle{TLSCertificate:<redacted> TLSPrivateKey:<redacted> WireGuardPrivateKey:<redacted>}"

func (CredentialBundle) String() string {
	return credentialBundleRedacted
}

func (CredentialBundle) GoString() string {
	return credentialBundleRedacted
}

// Format is deliberately a value-receiver method so formatting either a
// bundle pointer or a copied bundle value cannot fall back to fmt's recursive
// struct formatter and expose the owned byte slices.
func (CredentialBundle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, credentialBundleRedacted)
}

func (bundle *CredentialBundle) Close() {
	if bundle == nil {
		return
	}
	clearOwnedCredential(bundle.tlsCertificatePEM)
	clearOwnedCredential(bundle.tlsPrivateKeyPEM)
	clearOwnedCredential(bundle.wireGuardPrivateKey)
	bundle.tlsCertificatePEM = nil
	bundle.tlsPrivateKeyPEM = nil
	bundle.wireGuardPrivateKey = nil
}

func clearOwnedCredential(encoded []byte) {
	if encoded == nil {
		return
	}
	clear(encoded[:cap(encoded)])
}

// LoadSystemdCredentialBundle remains fail-closed until the separately locked
// invocation-bound CREDENTIALS_DIRECTORY and ACL-materialization reader is
// implemented. The Linux command exposes no live mode, so the superseded
// root-owned skeleton cannot become a credential-loading fallback.
func LoadSystemdCredentialBundle(Config) (*CredentialBundle, error) {
	return nil, ErrCredentialUnavailable
}

func validateCredentialBundle(config Config, bundle *CredentialBundle, roots *x509.CertPool) error {
	if config.Validate() != nil || bundle == nil || roots == nil {
		return ErrCredentialUnavailable
	}
	keyPair, err := tls.X509KeyPair(bundle.tlsCertificatePEM, bundle.tlsPrivateKeyPEM)
	if err != nil || len(keyPair.Certificate) == 0 {
		return ErrCredentialUnavailable
	}
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return ErrCredentialUnavailable
	}
	leafHash := sha256.Sum256(keyPair.Certificate[0])
	if subtle.ConstantTimeCompare(
		[]byte(hex.EncodeToString(leafHash[:])),
		[]byte(config.TLS.LocalCertificateSHA256),
	) != 1 {
		return ErrCredentialUnavailable
	}
	intermediates := x509.NewCertPool()
	for _, encoded := range keyPair.Certificate[1:] {
		certificate, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return ErrCredentialUnavailable
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       config.TLS.ServerName,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return ErrCredentialUnavailable
	}

	privateText := bundle.wireGuardPrivateKey
	if bytes.HasSuffix(privateText, []byte{'\n'}) {
		privateText = bytes.TrimSuffix(privateText, []byte{'\n'})
	}
	if bytes.IndexAny(privateText, "\r\n\t ") >= 0 {
		return ErrCredentialUnavailable
	}
	privateKey := make([]byte, base64.StdEncoding.DecodedLen(len(privateText)))
	decodedLength, err := base64.StdEncoding.Strict().Decode(privateKey, privateText)
	if err != nil || decodedLength != curve25519.ScalarSize {
		clear(privateKey)
		return ErrCredentialUnavailable
	}
	privateKey = privateKey[:decodedLength]
	defer clear(privateKey)
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		clear(publicKey)
		return ErrCredentialUnavailable
	}
	defer clear(publicKey)
	expectedPublicKey, validPublicKey := decodeKey(config.WireGuard.ServerPublicKeyBase64)
	defer clear(expectedPublicKey)
	if !validPublicKey || subtle.ConstantTimeCompare(publicKey, expectedPublicKey) != 1 {
		return ErrCredentialUnavailable
	}
	return nil
}

func validCredentialName(name string) bool {
	switch name {
	case TLSCertificateCredentialName, TLSPrivateKeyCredentialName, WireGuardPrivateCredentialName:
		return true
	default:
		return false
	}
}
