// Package productionpeer defines the fail-closed public configuration and
// lifecycle boundary for a future deployable Linux KyClash peer.
//
// This package intentionally contains no privileged Linux implementation yet.
// In particular, decoding a Config never opens a listener, creates a TUN
// device, changes forwarding, or mutates a route.
package productionpeer

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

const (
	ConfigSchemaVersion       = 2
	CarrierAuthVersionV1      = 1
	MaxConfigSize             = 64 * 1024
	MaxConfigJSONDepth        = 64
	MaxAuthorizedClients      = 1
	MaxPrivateCIDRs           = 16
	MaxPrivateCIDRTextBytes   = 1024
	RequiredShutdownGraceSecs = 10

	TLSSystemRoots = "system_roots"
	TLSVersion13   = "1.3"

	ClientAuthenticationWireGuard = "wireguard_public_key"
	ForwardingBrokeredLinuxTUNFD  = "brokered_linux_tun_fd"
	ReturnPathRouted              = "routed"

	TunnelInterface = "kyclash0"
	WSSPath         = "/kynp"
	QUICALPN        = "kyclash-network/1"
	TunnelMTU       = 1420

	SystemdUnitName                = "net.kysion.kyclash.network-peer.service"
	LinuxConfigDirectory           = "/etc/kyclash"
	LinuxConfigFileName            = "network-peer-v2.json"
	LinuxConfigPath                = LinuxConfigDirectory + "/" + LinuxConfigFileName
	TLSCertificateCredentialName   = "tls-chain.pem"
	TLSPrivateKeyCredentialName    = "tls-private-key.pem"
	WireGuardPrivateCredentialName = "wireguard-private-key"
)

var ErrInvalidConfig = errors.New("invalid production peer configuration")

var privateRouteAllowlist = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

type Config struct {
	SchemaVersion      uint8            `json:"schema_version"`
	CarrierAuthVersion uint8            `json:"carrier_auth_version"`
	PeerID             string           `json:"peer_id"`
	DeploymentID       string           `json:"deployment_id"`
	TLS                TLSConfig        `json:"tls"`
	WireGuard          WireGuardConfig  `json:"wireguard"`
	Listeners          []ListenerConfig `json:"listeners"`
	Forwarding         ForwardingConfig `json:"forwarding"`
	Policy             PolicyConfig     `json:"policy"`
}

type TLSConfig struct {
	ClientTrustMode        string `json:"trust_mode"`
	MinimumVersion         string `json:"minimum_version"`
	ServerName             string `json:"server_name"`
	LocalCertificateSHA256 string `json:"local_certificate_sha256"`
	ClientAuthentication   string `json:"client_authentication"`
}

type WireGuardConfig struct {
	ServerPublicKeyBase64 string         `json:"server_public_key_base64"`
	ServerAddresses       []string       `json:"server_addresses"`
	Clients               []ClientConfig `json:"clients"`
	MTU                   uint16         `json:"mtu"`
}

type ClientConfig struct {
	ID              string   `json:"id"`
	PublicKeyBase64 string   `json:"public_key_base64"`
	TunnelAddresses []string `json:"tunnel_addresses"`
}

type ListenerConfig struct {
	Transport profile.Transport `json:"transport"`
	Bind      string            `json:"bind"`
	URL       string            `json:"url"`
}

type ForwardingConfig struct {
	Mode            string           `json:"mode"`
	TunnelInterface string           `json:"tunnel_interface"`
	SiteInterface   string           `json:"site_interface"`
	PrivateCIDRs    []string         `json:"private_cidrs"`
	ReturnPath      ReturnPathConfig `json:"return_path"`
}

type ReturnPathConfig struct {
	Mode string `json:"mode"`
}

type PolicyConfig struct {
	MaxActiveClients               uint8  `json:"max_active_clients"`
	MaxActiveCarriers              uint8  `json:"max_active_carriers"`
	CarrierHandshakeTimeoutSeconds uint16 `json:"carrier_handshake_timeout_seconds"`
	HealthIntervalSeconds          uint16 `json:"health_interval_seconds"`
	IdleTimeoutSeconds             uint16 `json:"idle_timeout_seconds"`
	ShutdownGraceSeconds           uint16 `json:"shutdown_grace_seconds"`
}

func (candidate Config) String() string {
	return fmt.Sprintf(
		"Config{SchemaVersion:%d CarrierAuthVersion:%d PeerID:%q DeploymentID:%q TLS:<redacted> WireGuard:<redacted> Listeners:<redacted> Forwarding:<redacted>}",
		candidate.SchemaVersion,
		candidate.CarrierAuthVersion,
		candidate.PeerID,
		candidate.DeploymentID,
	)
}

func DecodeConfig(reader io.Reader) (*Config, error) {
	if reader == nil {
		return nil, ErrInvalidConfig
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaxConfigSize+1))
	if err != nil || len(encoded) == 0 || len(encoded) > MaxConfigSize {
		clear(encoded)
		return nil, ErrInvalidConfig
	}
	defer clear(encoded)
	if !uniqueJSONKeys(encoded) {
		return nil, ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var decoded Config
	if err := decoder.Decode(&decoded); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrInvalidConfig
	}
	if err := decoded.Validate(); err != nil {
		return nil, err
	}
	return &decoded, nil
}

func (candidate Config) Validate() error {
	if candidate.SchemaVersion != ConfigSchemaVersion ||
		candidate.CarrierAuthVersion != CarrierAuthVersionV1 ||
		!validID(candidate.PeerID) ||
		!validID(candidate.DeploymentID) ||
		!candidate.TLS.valid() ||
		!candidate.WireGuard.valid() ||
		!listenersValid(candidate.Listeners, candidate.TLS.ServerName) ||
		!candidate.Forwarding.valid(candidate.WireGuard) ||
		!candidate.Policy.valid() {
		return ErrInvalidConfig
	}
	return nil
}

func (candidate TLSConfig) valid() bool {
	return candidate.ClientTrustMode == TLSSystemRoots &&
		candidate.MinimumVersion == TLSVersion13 &&
		validServerName(candidate.ServerName) &&
		validSHA256(candidate.LocalCertificateSHA256) &&
		candidate.ClientAuthentication == ClientAuthenticationWireGuard
}

func (candidate WireGuardConfig) valid() bool {
	serverKey, serverOK := decodeKey(candidate.ServerPublicKeyBase64)
	defer clear(serverKey)
	if !serverOK ||
		len(candidate.Clients) != MaxAuthorizedClients ||
		candidate.MTU != TunnelMTU {
		return false
	}
	serverAddresses, serverFamilies, ok := hostPrefixes(candidate.ServerAddresses)
	if !ok {
		return false
	}
	seenIDs := make(map[string]bool, len(candidate.Clients))
	seenKeys := make(map[string]bool, len(candidate.Clients))
	clientPrefixes := make([]netip.Prefix, 0, len(candidate.Clients)*2)
	for _, client := range candidate.Clients {
		clientKey, clientOK := decodeKey(client.PublicKeyBase64)
		if !clientOK {
			clear(clientKey)
			return false
		}
		keyIdentity := string(clientKey)
		if !validID(client.ID) ||
			seenIDs[client.ID] ||
			seenKeys[keyIdentity] ||
			bytes.Equal(serverKey, clientKey) {
			clear(clientKey)
			return false
		}
		clear(clientKey)
		addresses, families, validAddresses := hostPrefixes(client.TunnelAddresses)
		if !validAddresses ||
			!sameFamilies(serverFamilies, families) ||
			prefixSetsOverlap(serverAddresses, addresses) ||
			prefixSetsOverlap(clientPrefixes, addresses) {
			return false
		}
		seenIDs[client.ID] = true
		seenKeys[keyIdentity] = true
		clientPrefixes = append(clientPrefixes, addresses...)
	}
	return true
}

func listenersValid(listeners []ListenerConfig, serverName string) bool {
	expected := [...]profile.Transport{profile.QUIC, profile.WSS, profile.TCP}
	if len(listeners) != len(expected) {
		return false
	}
	seenPorts := make(map[uint16]bool, len(listeners))
	seenURLs := make(map[string]bool, len(listeners))
	var commonAddress netip.Addr
	for index, listener := range listeners {
		if listener.Transport != expected[index] {
			return false
		}
		bind, err := netip.ParseAddrPort(listener.Bind)
		if err != nil ||
			listener.Bind != bind.String() ||
			!validUnderlayAddress(bind.Addr()) ||
			bind.Port() < 1024 ||
			seenPorts[bind.Port()] {
			return false
		}
		if index == 0 {
			commonAddress = bind.Addr()
		} else if bind.Addr() != commonAddress {
			return false
		}
		seenPorts[bind.Port()] = true
		parsed, err := url.Parse(listener.URL)
		canonicalPort := strconv.Itoa(int(bind.Port()))
		if err != nil ||
			parsed.User != nil ||
			parsed.Opaque != "" ||
			parsed.RawPath != "" ||
			parsed.RawQuery != "" ||
			parsed.ForceQuery ||
			parsed.Fragment != "" ||
			parsed.RawFragment != "" ||
			parsed.Hostname() == "" ||
			parsed.Hostname() != serverName ||
			parsed.Port() != canonicalPort ||
			parsed.Host != serverName+":"+canonicalPort ||
			parsed.String() != listener.URL ||
			seenURLs[parsed.String()] {
			return false
		}
		advertisedPort, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil || uint16(advertisedPort) != bind.Port() {
			return false
		}
		seenURLs[parsed.String()] = true
		switch listener.Transport {
		case profile.QUIC:
			if parsed.Scheme != "https" || parsed.Path != "" {
				return false
			}
		case profile.WSS:
			if parsed.Scheme != "wss" || parsed.Path != WSSPath {
				return false
			}
		case profile.TCP:
			if parsed.Scheme != "tcp" || parsed.Path != "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (candidate ForwardingConfig) valid(wireGuard WireGuardConfig) bool {
	if candidate.Mode != ForwardingBrokeredLinuxTUNFD ||
		candidate.TunnelInterface != TunnelInterface ||
		!validInterface(candidate.SiteInterface) ||
		candidate.SiteInterface == TunnelInterface ||
		candidate.ReturnPath.Mode != ReturnPathRouted {
		return false
	}
	privatePrefixes, privateFamilies, ok := privatePrefixes(candidate.PrivateCIDRs)
	if !ok {
		return false
	}
	serverPrefixes, serverFamilies, ok := hostPrefixes(wireGuard.ServerAddresses)
	if !ok || !sameFamilies(privateFamilies, serverFamilies) {
		return false
	}
	clientPrefixes := make([]netip.Prefix, 0, len(wireGuard.Clients)*2)
	for _, client := range wireGuard.Clients {
		prefixes, families, valid := hostPrefixes(client.TunnelAddresses)
		if !valid || !sameFamilies(privateFamilies, families) {
			return false
		}
		clientPrefixes = append(clientPrefixes, prefixes...)
	}
	return !prefixSetsOverlap(privatePrefixes, serverPrefixes) &&
		!prefixSetsOverlap(privatePrefixes, clientPrefixes)
}

func (candidate PolicyConfig) valid() bool {
	return candidate.MaxActiveClients == 1 &&
		candidate.MaxActiveCarriers == 1 &&
		candidate.CarrierHandshakeTimeoutSeconds >= 1 &&
		candidate.CarrierHandshakeTimeoutSeconds <= 30 &&
		candidate.HealthIntervalSeconds >= 1 &&
		candidate.HealthIntervalSeconds <= 60 &&
		candidate.IdleTimeoutSeconds >= 30 &&
		candidate.IdleTimeoutSeconds <= 900 &&
		candidate.ShutdownGraceSeconds == RequiredShutdownGraceSecs
}

func uniqueJSONKeys(encoded []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if !consumeUniqueJSONValue(decoder, 1) {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func consumeUniqueJSONValue(decoder *json.Decoder, depth int) bool {
	if depth > MaxConfigJSONDepth {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return true
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, isString := keyToken.(string)
			if keyErr != nil || !isString || seen[key] {
				return false
			}
			seen[key] = true
			if !consumeUniqueJSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, closingErr := decoder.Token()
		return closingErr == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !consumeUniqueJSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, closingErr := decoder.Token()
		return closingErr == nil && closing == json.Delim(']')
	default:
		return false
	}
}

func allClientTunnelAddresses(wireGuard WireGuardConfig) []string {
	count := 0
	for _, client := range wireGuard.Clients {
		count += len(client.TunnelAddresses)
	}
	result := make([]string, 0, count)
	for _, client := range wireGuard.Clients {
		result = append(result, client.TunnelAddresses...)
	}
	return result
}

func validID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if !isAlphaNumeric(character) &&
			(index == 0 || !strings.ContainsRune("._:-", character)) {
			return false
		}
	}
	return true
}

func validServerName(value string) bool {
	if strings.TrimSpace(value) != value || value == "" || len(value) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	if value != strings.ToLower(value) ||
		strings.HasSuffix(value, ".") ||
		numericDotOnly(value) {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" ||
			len(label) > 63 ||
			label[0] == '-' ||
			label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !isAlphaNumeric(character) && character != '-' {
				return false
			}
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return false
	}
	defer clear(decoded)
	for _, value := range decoded {
		if value != 0 {
			return true
		}
	}
	return false
}

func decodeKey(value string) ([]byte, bool) {
	if len(value) != base64.StdEncoding.EncodedLen(32) {
		return nil, false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return nil, false
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, false
	}
	for _, value := range decoded {
		if value != 0 {
			return decoded, true
		}
	}
	clear(decoded)
	return nil, false
}

func hostPrefixes(values []string) ([]netip.Prefix, map[bool]bool, bool) {
	if len(values) == 0 || len(values) > 2 {
		return nil, nil, false
	}
	result := make([]netip.Prefix, 0, len(values))
	families := make(map[bool]bool, len(values))
	seen := make(map[netip.Prefix]bool, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil ||
			value != prefix.String() ||
			prefix.Addr().Is4In6() ||
			prefix.Addr().Zone() != "" ||
			prefix != prefix.Masked() ||
			prefix.Bits() != prefix.Addr().BitLen() ||
			!validTunnelAddress(prefix.Addr()) ||
			seen[prefix] ||
			families[prefix.Addr().Is4()] {
			return nil, nil, false
		}
		seen[prefix] = true
		families[prefix.Addr().Is4()] = true
		result = append(result, prefix)
	}
	return result, families, true
}

func privatePrefixes(values []string) ([]netip.Prefix, map[bool]bool, bool) {
	if len(values) == 0 || len(values) > MaxPrivateCIDRs {
		return nil, nil, false
	}
	result := make([]netip.Prefix, 0, len(values))
	families := make(map[bool]bool)
	seen := make(map[netip.Prefix]bool, len(values))
	textBytes := 0
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil ||
			value != prefix.String() ||
			prefix.Addr().Is4In6() ||
			prefix.Addr().Zone() != "" ||
			prefix.Bits() == 0 ||
			prefix != prefix.Masked() ||
			!validPrivatePrefix(prefix) ||
			seen[prefix] {
			return nil, nil, false
		}
		textBytes += len(value)
		if textBytes > MaxPrivateCIDRTextBytes {
			return nil, nil, false
		}
		seen[prefix] = true
		families[prefix.Addr().Is4()] = true
		for _, existing := range result {
			if prefix.Overlaps(existing) {
				return nil, nil, false
			}
		}
		result = append(result, prefix)
	}
	return result, families, true
}

func prefixSetsOverlap(left, right []netip.Prefix) bool {
	for _, leftPrefix := range left {
		for _, rightPrefix := range right {
			if leftPrefix.Overlaps(rightPrefix) {
				return true
			}
		}
	}
	return false
}

func sameFamilies(left, right map[bool]bool) bool {
	return left[true] == right[true] && left[false] == right[false]
}

func validUnderlayAddress(value netip.Addr) bool {
	return value.IsValid() &&
		value.Is4() &&
		!value.Is4In6() &&
		value.Zone() == "" &&
		!value.IsUnspecified() &&
		!value.IsMulticast() &&
		!value.IsLoopback() &&
		!value.IsLinkLocalUnicast()
}

func validTunnelAddress(value netip.Addr) bool {
	return value.IsValid() &&
		!value.Is4In6() &&
		value.Zone() == "" &&
		value.IsPrivate() &&
		!value.IsUnspecified() &&
		!value.IsMulticast() &&
		!value.IsLoopback() &&
		!value.IsLinkLocalUnicast()
}

func validPrivatePrefix(value netip.Prefix) bool {
	if !value.IsValid() ||
		value.Addr().Is4In6() ||
		value.Addr().Zone() != "" ||
		value != value.Masked() {
		return false
	}
	for _, allowed := range privateRouteAllowlist {
		if value.Addr().BitLen() == allowed.Addr().BitLen() &&
			value.Bits() >= allowed.Bits() &&
			allowed.Contains(value.Addr()) {
			return true
		}
	}
	return false
}

func validInterface(value string) bool {
	if value == "" || len(value) > 15 || value == "lo" || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if !isAlphaNumeric(character) && character != '_' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

func isAlphaNumeric(character rune) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9'
}

func numericDotOnly(value string) bool {
	for _, character := range value {
		if character != '.' && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
