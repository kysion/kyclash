package externalpeer

import (
	"crypto/ed25519"
	"crypto/tls"
	"net/netip"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

type ClientPublicDescriptor struct {
	SchemaVersion                        uint8  `json:"schema_version"`
	RunID                                string `json:"run_id"`
	ExpiresAt                            int64  `json:"expires_at"`
	VMName                               string `json:"vm_name"`
	VirtualMacModel                      string `json:"virtual_mac_model"`
	PlatformUUID                         string `json:"platform_uuid"`
	En0PrivateIPv4                       string `json:"en0_private_ipv4"`
	En0MAC                               string `json:"en0_mac"`
	WireGuardPublicKey                   string `json:"wireguard_public_key"`
	TLSClientCSRDER_SHA256               string `json:"tls_client_csr_der_sha256"`
	TLSClientPublicKeySHA256             string `json:"tls_client_public_key_sha256"`
	OverlaySSHClientPublicKeySHA256      string `json:"overlay_ssh_client_public_key_sha256"`
	OverlaySSHClientPublicKeyFingerprint string `json:"overlay_ssh_client_public_key_fingerprint"`
}

// PeerPublicDescriptor is intentionally flat. This keeps the strict JSON
// authority surface auditable and prevents a later producer from hiding a
// caller-selected endpoint, path, or credential inside an open-ended object.
type PeerPublicDescriptor struct {
	SchemaVersion uint8 `json:"schema_version"`

	RunID     string `json:"run_id"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`

	ClientVMName         string `json:"client_vm_name"`
	ClientPlatformUUID   string `json:"client_platform_uuid"`
	PeerVMName           string `json:"peer_vm_name"`
	PeerPlatformUUID     string `json:"peer_platform_uuid"`
	BindInterface        string `json:"bind_interface"`
	PeerEn0PrivateIPv4   string `json:"peer_en0_private_ipv4"`
	ClientEn0PrivateIPv4 string `json:"client_en0_private_ipv4"`
	ClientEn0MAC         string `json:"client_en0_mac"`
	PeerEn0MAC           string `json:"peer_en0_mac"`

	Endpoints []profile.Endpoint `json:"endpoints"`

	PeerWireGuardPublicKey   string `json:"peer_wireguard_public_key"`
	ClientWireGuardPublicKey string `json:"client_wireguard_public_key"`
	PrivateEchoIPv4          string `json:"private_echo_ipv4"`
	PrivateEchoPort          uint16 `json:"private_echo_port"`

	PublicCADER_SHA256               string `json:"public_ca_der_sha256"`
	ServerCertificateSHA256          string `json:"server_certificate_sha256"`
	ServerCertificateIPSAN           string `json:"server_certificate_ip_san"`
	ServerCertificateNotBefore       int64  `json:"server_certificate_not_before"`
	ServerCertificateNotAfter        int64  `json:"server_certificate_not_after"`
	ClientCertificateSHA256          string `json:"client_certificate_sha256"`
	ClientCertificateIdentity        string `json:"client_certificate_identity"`
	ClientCertificatePublicKeySHA256 string `json:"client_certificate_public_key_sha256"`

	OverlaySSHAddress                    string `json:"overlay_ssh_address"`
	OverlaySSHServerPublicKeySHA256      string `json:"overlay_ssh_server_public_key_sha256"`
	OverlaySSHServerPublicKeyFingerprint string `json:"overlay_ssh_server_public_key_fingerprint"`
	OverlaySSHClientPublicKeySHA256      string `json:"overlay_ssh_client_public_key_sha256"`
	OverlaySSHClientPublicKeyFingerprint string `json:"overlay_ssh_client_public_key_fingerprint"`
	RunNonceSHA256                       string `json:"run_nonce_sha256"`

	SystemSSHProxyAddress             string `json:"system_ssh_proxy_address"`
	SystemSSHProxyTarget              string `json:"system_ssh_proxy_target"`
	SystemSSHRestrictedAccount        string `json:"system_ssh_restricted_account"`
	SystemSSHForcedCommand            string `json:"system_ssh_forced_command"`
	SystemSSHHostPublicKeySHA256      string `json:"system_ssh_host_public_key_sha256"`
	SystemSSHHostPublicKeyFingerprint string `json:"system_ssh_host_public_key_fingerprint"`

	TransportOrder  []profile.Transport `json:"transport_order"`
	QUICALPN        string              `json:"quic_alpn"`
	WSSPath         string              `json:"wss_path"`
	TLSVersion      string              `json:"tls_version"`
	MutualTLS       bool                `json:"mutual_tls"`
	InnerClientIPv4 string              `json:"inner_client_ipv4"`
	InnerPeerIPv4   string              `json:"inner_peer_ipv4"`
}

type ClientExpectation struct {
	RunID              string
	Now                time.Time
	ClientPlatformUUID string
	ClientIPv4         netip.Addr
	ClientMAC          string
	WireGuardPublicKey []byte
}

type PeerExpectation struct {
	RunID                    string
	Now                      time.Time
	ClientPlatformUUID       string
	PeerPlatformUUID         string
	ClientIPv4               netip.Addr
	PeerIPv4                 netip.Addr
	ClientMAC                string
	PeerMAC                  string
	ClientWireGuardPublicKey []byte
	ClientCSRDER             []byte
	OverlayClientPublicKey   []byte
}

type ClientPublicArtifacts struct {
	Descriptor             []byte
	TLSClientCSRDER        []byte
	OverlayClientPublicKey []byte
}

type PeerPublicArtifacts struct {
	Descriptor             []byte
	CADER                  []byte
	ServerCertificateDER   []byte
	ClientCertificateDER   []byte
	OverlayServerPublicKey []byte
	SystemSSHHostPublicKey []byte
	TransferManifest       []byte
}

// ClientIdentity contains client-owned private material. Call Clear after the
// last carrier and SSH probe. It must never be serialized.
type ClientIdentity struct {
	TLSPrivateKey     ed25519.PrivateKey
	TLSCSRDER         []byte
	OverlayPrivateKey ed25519.PrivateKey
	OverlayPublicKey  []byte
}

type PeerIdentity struct {
	ServerTLSCertificate tls.Certificate
	CADER                []byte
	ServerCertificateDER []byte
	ClientCertificateDER []byte
	OverlayPrivateKey    ed25519.PrivateKey
	OverlayPublicKey     []byte
	WireGuardPrivateKey  []byte
	WireGuardPublicKey   []byte
	RunNonce             []byte
}

func (identity *ClientIdentity) Clear() {
	if identity == nil {
		return
	}
	clear(identity.TLSPrivateKey)
	clear(identity.OverlayPrivateKey)
	clear(identity.TLSCSRDER)
	clear(identity.OverlayPublicKey)
	*identity = ClientIdentity{}
}

func (identity *PeerIdentity) Clear() {
	if identity == nil {
		return
	}
	for index := range identity.ServerTLSCertificate.Certificate {
		clear(identity.ServerTLSCertificate.Certificate[index])
	}
	if private, ok := identity.ServerTLSCertificate.PrivateKey.(ed25519.PrivateKey); ok {
		clear(private)
	}
	clear(identity.CADER)
	clear(identity.ServerCertificateDER)
	clear(identity.ClientCertificateDER)
	clear(identity.OverlayPrivateKey)
	clear(identity.OverlayPublicKey)
	clear(identity.WireGuardPrivateKey)
	clear(identity.WireGuardPublicKey)
	clear(identity.RunNonce)
	*identity = PeerIdentity{}
}
