package externalpeer

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/netip"
	"time"
)

const MaxChildControlFrame = 256 * 1024

type ChildBootstrap struct {
	SchemaVersion uint8  `json:"schema_version"`
	RunID         string `json:"run_id"`
	IssuedAt      int64  `json:"issued_at"`
	ExpiresAt     int64  `json:"expires_at"`

	ClientPlatformUUID           string `json:"client_platform_uuid"`
	ClientIPv4                   string `json:"client_ipv4"`
	ClientMAC                    string `json:"client_mac"`
	ClientWireGuardPublicKey     string `json:"client_wireguard_public_key"`
	ClientDescriptorBase64       string `json:"client_descriptor_base64"`
	ClientCSRDERBase64           string `json:"client_csr_der_base64"`
	ClientOverlayPublicKeyBase64 string `json:"client_overlay_public_key_base64"`

	PeerPlatformUUID             string `json:"peer_platform_uuid"`
	PeerIPv4                     string `json:"peer_ipv4"`
	PeerMAC                      string `json:"peer_mac"`
	SystemSSHHostPublicKeyBase64 string `json:"system_ssh_host_public_key_base64"`
}

type ChildCommand struct {
	Command string `json:"command"`
}

type ChildResponse struct {
	SchemaVersion   uint8  `json:"schema_version"`
	State           string `json:"state"`
	ActiveTransport string `json:"active_transport,omitempty"`
	QUICBlocked     bool   `json:"quic_blocked,omitempty"`
	WSSRefused      bool   `json:"wss_refused,omitempty"`
	DroppedQUIC     uint64 `json:"dropped_quic,omitempty"`
	ErrorCode       string `json:"error_code,omitempty"`

	PeerDescriptorBase64         string `json:"peer_descriptor_base64,omitempty"`
	CADERBase64                  string `json:"ca_der_base64,omitempty"`
	ServerCertificateDERBase64   string `json:"server_certificate_der_base64,omitempty"`
	ClientCertificateDERBase64   string `json:"client_certificate_der_base64,omitempty"`
	OverlayServerPublicKeyBase64 string `json:"overlay_server_public_key_base64,omitempty"`
	SystemSSHHostPublicKeyBase64 string `json:"system_ssh_host_public_key_base64,omitempty"`
	TransferManifestBase64       string `json:"transfer_manifest_base64,omitempty"`
	RunNonceBase64               string `json:"run_nonce_base64,omitempty"`
}

func RunPeerChild(ctx context.Context, input io.Reader, output io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if input == nil || output == nil {
		return ErrInvalidPeerConfig
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), MaxChildControlFrame)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return err
		}
		return io.ErrUnexpectedEOF
	}
	config, err := DecodeChildBootstrap(scanner.Bytes())
	if err != nil {
		return err
	}
	peer, err := StartPeer(ctx, config)
	clearPeerConfigPublicArtifacts(&config)
	if err != nil {
		_ = writeChildResponse(output, ChildResponse{
			SchemaVersion: SchemaVersion,
			State:         "failed",
			ErrorCode:     "peer_start_failed",
		})
		return err
	}
	defer peer.Close()
	artifacts := peer.PublicArtifacts()
	defer clearPeerArtifacts(&artifacts)
	runNonce := peer.runNonce()
	defer clear(runNonce)
	if len(runNonce) != 32 {
		return ErrPeerChildClosed
	}
	if err := writeChildResponse(output, ChildResponse{
		SchemaVersion:                SchemaVersion,
		State:                        "ready",
		PeerDescriptorBase64:         base64.StdEncoding.EncodeToString(artifacts.Descriptor),
		CADERBase64:                  base64.StdEncoding.EncodeToString(artifacts.CADER),
		ServerCertificateDERBase64:   base64.StdEncoding.EncodeToString(artifacts.ServerCertificateDER),
		ClientCertificateDERBase64:   base64.StdEncoding.EncodeToString(artifacts.ClientCertificateDER),
		OverlayServerPublicKeyBase64: base64.StdEncoding.EncodeToString(artifacts.OverlayServerPublicKey),
		SystemSSHHostPublicKeyBase64: base64.StdEncoding.EncodeToString(artifacts.SystemSSHHostPublicKey),
		TransferManifestBase64:       base64.StdEncoding.EncodeToString(artifacts.TransferManifest),
		RunNonceBase64:               base64.StdEncoding.EncodeToString(runNonce),
	}); err != nil {
		return err
	}
	for scanner.Scan() {
		var command ChildCommand
		if err := strictDecode(scanner.Bytes(), &command); err != nil {
			return ErrInvalidPeerConfig
		}
		switch command.Command {
		case "block_quic_udp":
			peer.BlockQUICUDP()
		case "refuse_wss":
			peer.RefuseWSS()
		case "status":
		case "stop":
			if err := peer.Close(); err != nil {
				return err
			}
			return writeChildResponse(output, ChildResponse{
				SchemaVersion: SchemaVersion,
				State:         "stopped",
			})
		default:
			return ErrInvalidPeerConfig
		}
		status := peer.Status()
		if err := writeChildResponse(output, ChildResponse{
			SchemaVersion:   SchemaVersion,
			State:           "running",
			ActiveTransport: string(status.ActiveTransport),
			QUICBlocked:     status.QUICBlocked,
			WSSRefused:      status.WSSRefused,
			DroppedQUIC:     status.DroppedQUIC,
		}); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	// Authenticated controller EOF is a terminal cleanup event.
	return peer.Close()
}

func DecodeChildBootstrap(data []byte) (PeerConfig, error) {
	var value ChildBootstrap
	if err := strictDecode(data, &value); err != nil {
		return PeerConfig{}, ErrInvalidPeerConfig
	}
	clientIP, clientErr := netip.ParseAddr(value.ClientIPv4)
	peerIP, peerErr := netip.ParseAddr(value.PeerIPv4)
	wireGuardPublic, wireGuardErr := base64.StdEncoding.Strict().DecodeString(value.ClientWireGuardPublicKey)
	descriptor, descriptorErr := decodeBoundedBase64(value.ClientDescriptorBase64)
	csrDER, csrErr := decodeBoundedBase64(value.ClientCSRDERBase64)
	overlayPublic, overlayErr := decodeBoundedBase64(value.ClientOverlayPublicKeyBase64)
	systemHostPublic, systemErr := decodeBoundedBase64(value.SystemSSHHostPublicKeyBase64)
	if value.SchemaVersion != SchemaVersion ||
		!validRunID(value.RunID) ||
		clientErr != nil ||
		peerErr != nil ||
		wireGuardErr != nil ||
		len(wireGuardPublic) != 32 ||
		descriptorErr != nil ||
		csrErr != nil ||
		overlayErr != nil ||
		systemErr != nil {
		clear(wireGuardPublic)
		clear(descriptor)
		clear(csrDER)
		clear(overlayPublic)
		clear(systemHostPublic)
		return PeerConfig{}, ErrInvalidPeerConfig
	}
	issuedAt := time.Unix(value.IssuedAt, 0).UTC()
	expiresAt := time.Unix(value.ExpiresAt, 0).UTC()
	config := PeerConfig{
		RunID:     value.RunID,
		Now:       issuedAt,
		ExpiresAt: expiresAt,
		Client: ClientExpectation{
			RunID:              value.RunID,
			Now:                issuedAt,
			ClientPlatformUUID: value.ClientPlatformUUID,
			ClientIPv4:         clientIP,
			ClientMAC:          value.ClientMAC,
			WireGuardPublicKey: wireGuardPublic,
		},
		ClientArtifacts: ClientPublicArtifacts{
			Descriptor:             descriptor,
			TLSClientCSRDER:        csrDER,
			OverlayClientPublicKey: overlayPublic,
		},
		PeerPlatformUUID:       value.PeerPlatformUUID,
		PeerIPv4:               peerIP,
		PeerMAC:                value.PeerMAC,
		SystemSSHHostPublicKey: systemHostPublic,
	}
	if err := validatePeerConfig(config); err != nil ||
		!issuedAt.After(time.Now().UTC().Add(-30*time.Second)) ||
		issuedAt.After(time.Now().UTC().Add(30*time.Second)) ||
		!expiresAt.After(issuedAt.Add(MinRemainingLife)) ||
		expiresAt.After(issuedAt.Add(MaxRunLifetime)) {
		clearPeerConfigPublicArtifacts(&config)
		return PeerConfig{}, ErrInvalidPeerConfig
	}
	return config, nil
}

func writeChildResponse(output io.Writer, value ChildResponse) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > MaxChildControlFrame {
		return ErrInvalidPeerConfig
	}
	data = append(data, '\n')
	_, err = output.Write(data)
	clear(data)
	return err
}

func decodeBoundedBase64(value string) ([]byte, error) {
	if value == "" || len(value) > MaxArtifactSize*2 {
		return nil, ErrInvalidArtifact
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > MaxArtifactSize {
		clear(decoded)
		return nil, ErrInvalidArtifact
	}
	return decoded, nil
}

func clearPeerConfigPublicArtifacts(config *PeerConfig) {
	if config == nil {
		return
	}
	clear(config.Client.WireGuardPublicKey)
	clear(config.ClientArtifacts.Descriptor)
	clear(config.ClientArtifacts.TLSClientCSRDER)
	clear(config.ClientArtifacts.OverlayClientPublicKey)
	clear(config.SystemSSHHostPublicKey)
}
