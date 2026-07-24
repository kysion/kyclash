package externalpeer

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"golang.org/x/crypto/ssh"
)

var (
	ErrInvalidDescriptor = errors.New("invalid external-peer descriptor")
	ErrInvalidArtifact   = errors.New("invalid external-peer public artifact")
	ErrDuplicateJSONKey  = errors.New("duplicate JSON object key")
)

func EncodeClientPublicDescriptor(value ClientPublicDescriptor) ([]byte, error) {
	if err := validateClientDescriptor(value, time.Now().UTC()); err != nil {
		return nil, err
	}
	return marshalBounded(value)
}

func ParseClientPublicDescriptor(
	data []byte,
	now time.Time,
) (ClientPublicDescriptor, error) {
	var value ClientPublicDescriptor
	if err := strictDecode(data, &value); err != nil {
		return ClientPublicDescriptor{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validateClientDescriptor(value, now); err != nil {
		return ClientPublicDescriptor{}, err
	}
	return value, nil
}

func DecodeClientPublicDescriptor(
	data []byte,
	artifacts ClientPublicArtifacts,
	expected ClientExpectation,
) (ClientPublicDescriptor, error) {
	var value ClientPublicDescriptor
	if err := strictDecode(data, &value); err != nil {
		return ClientPublicDescriptor{}, err
	}
	now := expected.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validateClientDescriptor(value, now); err != nil {
		return ClientPublicDescriptor{}, err
	}
	if value.RunID != expected.RunID ||
		value.VMName != ClientVMName ||
		value.ClientFactsMismatch(expected) {
		return ClientPublicDescriptor{}, ErrInvalidDescriptor
	}
	if !equalBase64Key(value.WireGuardPublicKey, expected.WireGuardPublicKey) {
		return ClientPublicDescriptor{}, ErrInvalidDescriptor
	}
	if !bytes.Equal(data, artifacts.Descriptor) ||
		!hashMatches(value.TLSClientCSRDER_SHA256, artifacts.TLSClientCSRDER) ||
		!hashMatches(value.OverlaySSHClientPublicKeySHA256, artifacts.OverlayClientPublicKey) {
		return ClientPublicDescriptor{}, ErrInvalidArtifact
	}
	csrPublicHash, err := validateClientCSR(artifacts.TLSClientCSRDER, value.RunID)
	if err != nil || csrPublicHash != value.TLSClientPublicKeySHA256 {
		return ClientPublicDescriptor{}, ErrInvalidArtifact
	}
	if err := validateCanonicalSSHPublic(
		artifacts.OverlayClientPublicKey,
		value.OverlaySSHClientPublicKeyFingerprint,
	); err != nil {
		return ClientPublicDescriptor{}, err
	}
	return value, nil
}

func (value ClientPublicDescriptor) ClientFactsMismatch(expected ClientExpectation) bool {
	return value.PlatformUUID != expected.ClientPlatformUUID ||
		value.En0PrivateIPv4 != expected.ClientIPv4.String() ||
		!equalMAC(value.En0MAC, expected.ClientMAC)
}

func EncodePeerPublicDescriptor(value PeerPublicDescriptor) ([]byte, error) {
	if err := validatePeerDescriptor(value, time.Now().UTC()); err != nil {
		return nil, err
	}
	return marshalBounded(value)
}

func DecodePeerPublicDescriptor(
	data []byte,
	artifacts PeerPublicArtifacts,
	expected PeerExpectation,
) (PeerPublicDescriptor, error) {
	var value PeerPublicDescriptor
	if err := strictDecode(data, &value); err != nil {
		return PeerPublicDescriptor{}, err
	}
	now := expected.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validatePeerDescriptor(value, now); err != nil {
		return PeerPublicDescriptor{}, err
	}
	if !bytes.Equal(data, artifacts.Descriptor) ||
		value.RunID != expected.RunID ||
		value.ClientVMName != ClientVMName ||
		value.PeerVMName != PeerVMName ||
		value.ClientPlatformUUID != expected.ClientPlatformUUID ||
		value.PeerPlatformUUID != expected.PeerPlatformUUID ||
		value.ClientEn0PrivateIPv4 != expected.ClientIPv4.String() ||
		value.PeerEn0PrivateIPv4 != expected.PeerIPv4.String() ||
		!equalMAC(value.ClientEn0MAC, expected.ClientMAC) ||
		!equalMAC(value.PeerEn0MAC, expected.PeerMAC) ||
		!equalBase64Key(value.ClientWireGuardPublicKey, expected.ClientWireGuardPublicKey) {
		return PeerPublicDescriptor{}, ErrInvalidDescriptor
	}
	if err := validateEndpointSet(value.Endpoints, expected.PeerIPv4, expected.ClientIPv4); err != nil {
		return PeerPublicDescriptor{}, err
	}
	if !hashMatches(value.PublicCADER_SHA256, artifacts.CADER) ||
		!hashMatches(value.ServerCertificateSHA256, artifacts.ServerCertificateDER) ||
		!hashMatches(value.ClientCertificateSHA256, artifacts.ClientCertificateDER) ||
		!hashMatches(value.OverlaySSHServerPublicKeySHA256, artifacts.OverlayServerPublicKey) ||
		!hashMatches(value.SystemSSHHostPublicKeySHA256, artifacts.SystemSSHHostPublicKey) {
		return PeerPublicDescriptor{}, ErrInvalidArtifact
	}
	if err := ValidatePublicCertificateArtifacts(value, artifacts, expected); err != nil {
		return PeerPublicDescriptor{}, err
	}
	if err := validateCanonicalSSHPublic(
		artifacts.OverlayServerPublicKey,
		value.OverlaySSHServerPublicKeyFingerprint,
	); err != nil {
		return PeerPublicDescriptor{}, err
	}
	if err := validateCanonicalSSHPublic(
		artifacts.SystemSSHHostPublicKey,
		value.SystemSSHHostPublicKeyFingerprint,
	); err != nil {
		return PeerPublicDescriptor{}, err
	}
	manifestPayloads := [][]byte{
		artifacts.Descriptor,
		artifacts.CADER,
		artifacts.ServerCertificateDER,
		artifacts.ClientCertificateDER,
		artifacts.OverlayServerPublicKey,
		artifacts.SystemSSHHostPublicKey,
	}
	manifestFiles := make([]CourierFile, 0, len(manifestPayloads))
	for index, payload := range manifestPayloads {
		file, err := NewCourierFile(PeerArtifactNames[index], payload)
		if err != nil {
			return PeerPublicDescriptor{}, err
		}
		manifestFiles = append(manifestFiles, file)
	}
	if _, err := DecodeTransferManifest(
		artifacts.TransferManifest,
		value.RunID,
		CourierPeerToClient,
		manifestFiles,
	); err != nil {
		return PeerPublicDescriptor{}, err
	}
	if !hashMatches(value.OverlaySSHClientPublicKeySHA256, expected.OverlayClientPublicKey) {
		return PeerPublicDescriptor{}, ErrInvalidArtifact
	}
	if err := validateCanonicalSSHPublic(
		expected.OverlayClientPublicKey,
		value.OverlaySSHClientPublicKeyFingerprint,
	); err != nil {
		return PeerPublicDescriptor{}, err
	}
	return value, nil
}

func validateClientDescriptor(value ClientPublicDescriptor, now time.Time) error {
	if value.SchemaVersion != SchemaVersion ||
		!validRunID(value.RunID) ||
		value.VMName != ClientVMName ||
		!strings.HasPrefix(value.VirtualMacModel, "VirtualMac") ||
		!validUUID(value.PlatformUUID) ||
		!validPrivateUnderlay(value.En0PrivateIPv4) ||
		!validMAC(value.En0MAC) ||
		!validBase64Key(value.WireGuardPublicKey) ||
		!validSHA256(value.TLSClientCSRDER_SHA256) ||
		!validSHA256(value.TLSClientPublicKeySHA256) ||
		!validSHA256(value.OverlaySSHClientPublicKeySHA256) ||
		!validSSHFingerprint(value.OverlaySSHClientPublicKeyFingerprint) ||
		!validLifetime(value.ExpiresAt, now) {
		return ErrInvalidDescriptor
	}
	return nil
}

func validatePeerDescriptor(value PeerPublicDescriptor, now time.Time) error {
	peerIP, peerErr := netip.ParseAddr(value.PeerEn0PrivateIPv4)
	clientIP, clientErr := netip.ParseAddr(value.ClientEn0PrivateIPv4)
	if value.SchemaVersion != SchemaVersion ||
		!validRunID(value.RunID) ||
		value.ClientVMName != ClientVMName ||
		value.PeerVMName != PeerVMName ||
		!validUUID(value.ClientPlatformUUID) ||
		!validUUID(value.PeerPlatformUUID) ||
		value.ClientPlatformUUID == value.PeerPlatformUUID ||
		value.BindInterface != BindInterface ||
		peerErr != nil || clientErr != nil ||
		!validUnderlayPair(clientIP, peerIP) ||
		!validMAC(value.ClientEn0MAC) ||
		!validMAC(value.PeerEn0MAC) ||
		equalMAC(value.ClientEn0MAC, value.PeerEn0MAC) ||
		!validBase64Key(value.PeerWireGuardPublicKey) ||
		!validBase64Key(value.ClientWireGuardPublicKey) ||
		value.PeerWireGuardPublicKey == value.ClientWireGuardPublicKey ||
		value.PrivateEchoIPv4 != InnerPeerIPv4 ||
		value.PrivateEchoPort != PrivateEchoPort ||
		!validSHA256(value.PublicCADER_SHA256) ||
		!validSHA256(value.ServerCertificateSHA256) ||
		value.ServerCertificateIPSAN != peerIP.String() ||
		!validSHA256(value.ClientCertificateSHA256) ||
		value.ClientCertificateIdentity != clientCertificateIdentity(value.RunID) ||
		!validSHA256(value.ClientCertificatePublicKeySHA256) ||
		value.OverlaySSHAddress != net.JoinHostPort(InnerPeerIPv4, strconv.Itoa(int(OverlaySSHPort))) ||
		!validSHA256(value.OverlaySSHServerPublicKeySHA256) ||
		!validSSHFingerprint(value.OverlaySSHServerPublicKeyFingerprint) ||
		!validSHA256(value.OverlaySSHClientPublicKeySHA256) ||
		!validSSHFingerprint(value.OverlaySSHClientPublicKeyFingerprint) ||
		!validSHA256(value.RunNonceSHA256) ||
		value.SystemSSHProxyAddress != net.JoinHostPort(InnerPeerIPv4, strconv.Itoa(int(SystemSSHPort))) ||
		value.SystemSSHProxyTarget != "127.0.0.1:22" ||
		value.SystemSSHRestrictedAccount != "kyclashlabssh" ||
		value.SystemSSHForcedCommand != ForcedCommandName ||
		!validSHA256(value.SystemSSHHostPublicKeySHA256) ||
		!validSSHFingerprint(value.SystemSSHHostPublicKeyFingerprint) ||
		!equalTransportOrder(value.TransportOrder) ||
		value.QUICALPN != QUICALPN ||
		value.WSSPath != WSSPath ||
		value.TLSVersion != "1.3" ||
		!value.MutualTLS ||
		value.InnerClientIPv4 != InnerClientIPv4 ||
		value.InnerPeerIPv4 != InnerPeerIPv4 ||
		!validIssuedLifetime(value.IssuedAt, value.ExpiresAt, now) {
		return ErrInvalidDescriptor
	}
	if value.ServerCertificateNotBefore > now.Add(30*time.Second).Unix() ||
		value.ServerCertificateNotAfter != value.ExpiresAt ||
		value.ServerCertificateNotBefore >= value.ServerCertificateNotAfter {
		return ErrInvalidDescriptor
	}
	return validateEndpointSet(value.Endpoints, peerIP, clientIP)
}

func validateEndpointSet(endpoints []profile.Endpoint, peerIP, clientIP netip.Addr) error {
	expected := [...]profile.Transport{profile.QUIC, profile.WSS, profile.TCP}
	if len(endpoints) != len(expected) || !validUnderlayPair(clientIP, peerIP) {
		return ErrInvalidDescriptor
	}
	ports := make(map[uint16]struct{}, len(expected))
	for index, endpoint := range endpoints {
		if endpoint.Transport != expected[index] {
			return ErrInvalidDescriptor
		}
		parsed, err := url.Parse(endpoint.URL)
		if err != nil ||
			parsed.User != nil ||
			parsed.RawQuery != "" ||
			parsed.Fragment != "" ||
			parsed.Hostname() != peerIP.String() {
			return ErrInvalidDescriptor
		}
		if parsed.Hostname() == clientIP.String() {
			return ErrInvalidDescriptor
		}
		portValue, err := strconv.ParseUint(parsed.Port(), 10, 16)
		port := uint16(portValue)
		if err != nil || port < MinCarrierPort || port > MaxCarrierPort {
			return ErrInvalidDescriptor
		}
		if _, exists := ports[port]; exists {
			return ErrInvalidDescriptor
		}
		ports[port] = struct{}{}
		switch endpoint.Transport {
		case profile.QUIC:
			if parsed.Scheme != "https" || parsed.Path != "" {
				return ErrInvalidDescriptor
			}
		case profile.WSS:
			if parsed.Scheme != "wss" || parsed.Path != WSSPath {
				return ErrInvalidDescriptor
			}
		case profile.TCP:
			if parsed.Scheme != "tcp" || parsed.Path != "" {
				return ErrInvalidDescriptor
			}
		default:
			return ErrInvalidDescriptor
		}
	}
	return nil
}

func validUnderlayPair(client, peer netip.Addr) bool {
	return validPrivateAddr(client) &&
		validPrivateAddr(peer) &&
		client != peer &&
		!innerPrefix().Contains(client) &&
		!innerPrefix().Contains(peer)
}

func validPrivateUnderlay(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && validPrivateAddr(address) && !innerPrefix().Contains(address)
}

func validPrivateAddr(address netip.Addr) bool {
	return address.IsValid() &&
		address.Is4() &&
		address.IsPrivate() &&
		!address.IsLoopback() &&
		!address.IsUnspecified() &&
		!address.IsLinkLocalUnicast() &&
		!address.IsMulticast()
}

func innerPrefix() netip.Prefix { return netip.MustParsePrefix("10.88.0.0/24") }

func equalTransportOrder(values []profile.Transport) bool {
	return len(values) == 3 &&
		values[0] == profile.QUIC &&
		values[1] == profile.WSS &&
		values[2] == profile.TCP
}

func validLifetime(expiresAt int64, now time.Time) bool {
	expires := time.Unix(expiresAt, 0)
	return expires.After(now.Add(MinRemainingLife)) &&
		!expires.After(now.Add(MaxRunLifetime))
}

func validIssuedLifetime(issuedAt, expiresAt int64, now time.Time) bool {
	issued := time.Unix(issuedAt, 0)
	expires := time.Unix(expiresAt, 0)
	return !issued.After(now.Add(30*time.Second)) &&
		!issued.Before(now.Add(-30*time.Second)) &&
		expires.After(now.Add(MinRemainingLife)) &&
		!expires.After(issued.Add(MaxRunLifetime))
}

func validRunID(value string) bool {
	if len(value) < 8 || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			index > 0 && character == '-' {
			continue
		}
		return false
	}
	return value[len(value)-1] != '-'
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !(character >= '0' && character <= '9') &&
			!(character >= 'a' && character <= 'f') &&
			!(character >= 'A' && character <= 'F') {
			return false
		}
	}
	return true
}

func validMAC(value string) bool {
	parsed, err := net.ParseMAC(value)
	if err != nil || len(parsed) != 6 {
		return false
	}
	allZero := true
	for _, octet := range parsed {
		allZero = allZero && octet == 0
	}
	return !allZero && parsed[0]&1 == 0
}

func equalMAC(left, right string) bool {
	leftMAC, leftErr := net.ParseMAC(left)
	rightMAC, rightErr := net.ParseMAC(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftMAC, rightMAC)
}

func validBase64Key(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	valid := err == nil && len(decoded) == 32
	clear(decoded)
	return valid
}

func equalBase64Key(encoded string, raw []byte) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	defer clear(decoded)
	return err == nil && len(decoded) == 32 && bytes.Equal(decoded, raw)
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func hashMatches(expected string, data []byte) bool {
	sum := sha256.Sum256(data)
	return validSHA256(expected) && expected == hex.EncodeToString(sum[:])
}

func HashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validSSHFingerprint(value string) bool {
	return strings.HasPrefix(value, "SHA256:") && len(value) > len("SHA256:")
}

func validateCanonicalSSHPublic(raw []byte, fingerprint string) error {
	if len(raw) == 0 || len(raw) > 512 {
		return ErrInvalidArtifact
	}
	key, err := ssh.ParsePublicKey(raw)
	if err != nil ||
		key.Type() != ssh.KeyAlgoED25519 ||
		!bytes.Equal(key.Marshal(), raw) ||
		ssh.FingerprintSHA256(key) != fingerprint {
		return ErrInvalidArtifact
	}
	return nil
}

func marshalBounded(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > MaxDescriptorSize {
		return nil, ErrInvalidDescriptor
	}
	return append(data, '\n'), nil
}

func strictDecode(data []byte, output any) error {
	if len(data) == 0 || len(data) > MaxDescriptorSize || !utf8.Valid(data) {
		return ErrInvalidDescriptor
	}
	if err := rejectDuplicateObjectKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return ErrInvalidDescriptor
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalidDescriptor
	}
	return nil
}

func rejectDuplicateObjectKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeUniqueJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidDescriptor
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrInvalidDescriptor
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidDescriptor
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return ErrInvalidDescriptor
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("%w: %s", ErrDuplicateJSONKey, key)
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalidDescriptor
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalidDescriptor
		}
	default:
		return ErrInvalidDescriptor
	}
	return nil
}
