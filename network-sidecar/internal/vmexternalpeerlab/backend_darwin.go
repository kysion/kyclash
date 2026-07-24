//go:build darwin && kyclash_utun && kyclash_vm_external_peer_lab

package vmexternalpeerlab

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/userspace"
)

// NewBackend is available only in the reviewed real-utun external-peer build.
// Exact TLS 1.3 and the fixed echo verifier are not caller-selectable.
func NewBackend(
	privateKey []byte,
	roots *x509.CertPool,
	clientCertificate tls.Certificate,
	strictProfile *profile.Profile,
	instanceID string,
	supervisor SupervisorClient,
	ssh SSHVerifier,
) (*Backend, error) {
	if roots == nil || len(roots.Subjects()) == 0 {
		return nil, ErrInvalidBackendState
	}
	base, err := userspace.NewWithMutualTLS(
		privateKey,
		roots,
		userspace.MutualTLSConfig{
			ClientCertificate: clientCertificate,
			ExactTLS13:        true,
		},
		instanceID,
	)
	if err != nil {
		return nil, err
	}
	backend, err := newBackend(
		base,
		strictProfile,
		instanceID,
		supervisor,
		fixedEchoVerifier{},
		ssh,
	)
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	return backend, nil
}
