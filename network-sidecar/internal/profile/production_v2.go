package profile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/curve25519"
)

const (
	ProductionSchemaVersionV2      = 2
	ProductionCarrierAuthVersionV1 = 1
	ProductionTunnelMTU            = 1_420
	ProductionQUICALPN             = "kyclash-network/1"
	ProductionWSSPath              = "/kynp"

	MaxProductionProfileV2Size          = 64 * 1024
	MaxProductionProfileV2JSONDepth     = 64
	MaxProductionProfileV2PrivateCIDRs  = 16
	MaxProductionProfileV2CIDRTextBytes = 1024
)

var ErrInvalidProductionProfileV2 = errors.New("invalid production network profile v2")

var productionPrivateRouteAllowlist = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

var productionX25519FieldPrime = [curve25519.PointSize]byte{
	0xed,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x7f,
}

// ProductionProfileV2 is the strict, secret-free signed profile used only by
// the production networking path. Profile remains the independent v1 lab
// contract and is not implicitly upgraded by this type.
type ProductionProfileV2 struct {
	SchemaVersion      uint8                  `json:"schema_version"`
	CarrierAuthVersion uint8                  `json:"carrier_auth_version"`
	ProfileID          string                 `json:"profile_id"`
	ControlPlane       string                 `json:"control_plane"`
	IdentityRef        string                 `json:"identity_ref"`
	Site               ProductionSiteV2       `json:"site"`
	Tunnel             ProductionTunnelV2     `json:"tunnel"`
	Transports         ProductionTransportsV2 `json:"transports"`
	Policy             ProductionPolicyV2     `json:"policy"`
}

type ProductionSiteV2 struct {
	ID           string   `json:"id"`
	DisplayName  string   `json:"display_name"`
	PrivateCIDRs []string `json:"private_cidrs"`
}

type ProductionTunnelV2 struct {
	LocalAddresses   []string `json:"local_addresses"`
	LocalPublicKey   string   `json:"local_public_key"`
	PeerPublicKey    string   `json:"peer_public_key"`
	KeepaliveSeconds uint16   `json:"keepalive_seconds"`
}

type ProductionTransportsV2 struct {
	Primary   Transport              `json:"primary"`
	Fallbacks []Transport            `json:"fallbacks"`
	Endpoints []ProductionEndpointV2 `json:"endpoints"`
}

type ProductionEndpointV2 struct {
	Transport Transport `json:"transport"`
	URL       string    `json:"url"`
}

type ProductionPolicyV2 struct {
	ConnectTimeoutSeconds uint16 `json:"connect_timeout_seconds"`
	HealthIntervalSeconds uint16 `json:"health_interval_seconds"`
	FallbackThreshold     uint8  `json:"fallback_threshold"`
}

type NormalizedProductionEndpointV2 struct {
	Transport  Transport
	URL        string
	Address    string
	ServerName string
	Port       uint16
}

func (candidate ProductionProfileV2) String() string {
	return fmt.Sprintf(
		"ProductionProfileV2{SchemaVersion:%d CarrierAuthVersion:%d ProfileID:%q SiteID:%q Tunnel:<redacted> Endpoints:<redacted>}",
		candidate.SchemaVersion,
		candidate.CarrierAuthVersion,
		candidate.ProfileID,
		candidate.Site.ID,
	)
}

// DecodeProductionProfileV2 rejects ambiguous or unbounded JSON before
// validating the production-only semantic contract.
func DecodeProductionProfileV2(reader io.Reader) (*ProductionProfileV2, error) {
	if reader == nil {
		return nil, ErrInvalidProductionProfileV2
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaxProductionProfileV2Size+1))
	if err != nil ||
		len(encoded) == 0 ||
		len(encoded) > MaxProductionProfileV2Size ||
		!utf8.Valid(encoded) ||
		!validProductionProfileV2JSONStringScalars(encoded) {
		clear(encoded)
		return nil, ErrInvalidProductionProfileV2
	}
	defer clear(encoded)
	if !uniqueProductionProfileV2JSONKeys(encoded) ||
		!exactProductionProfileV2JSONKeys(encoded) {
		return nil, ErrInvalidProductionProfileV2
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var decoded ProductionProfileV2
	if err := decoder.Decode(&decoded); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrInvalidProductionProfileV2
	}
	if err := decoded.Validate(); err != nil {
		return nil, err
	}
	return &decoded, nil
}

func (candidate ProductionProfileV2) Validate() error {
	localKey, localKeyOK := decodeProductionPublicKey(candidate.Tunnel.LocalPublicKey)
	defer clear(localKey)
	peerKey, peerKeyOK := decodeProductionPublicKey(candidate.Tunnel.PeerPublicKey)
	defer clear(peerKey)
	localAddresses, localFamilies, localAddressesOK := productionHostPrefixes(candidate.Tunnel.LocalAddresses)
	privateCIDRs, privateFamilies, privateCIDRsOK := productionPrivatePrefixes(candidate.Site.PrivateCIDRs)
	if candidate.SchemaVersion != ProductionSchemaVersionV2 ||
		candidate.CarrierAuthVersion != ProductionCarrierAuthVersionV1 ||
		!validID(candidate.ProfileID) ||
		!validProductionControlPlane(candidate.ControlPlane) ||
		!validProductionIdentityRef(candidate.IdentityRef) ||
		!validID(candidate.Site.ID) ||
		!validProductionDisplayName(candidate.Site.DisplayName) ||
		!localKeyOK ||
		!peerKeyOK ||
		bytes.Equal(localKey, peerKey) ||
		candidate.Tunnel.KeepaliveSeconds == 0 ||
		!localAddressesOK ||
		!privateCIDRsOK ||
		!sameProductionFamilies(localFamilies, privateFamilies) ||
		productionPrefixSetsOverlap(localAddresses, privateCIDRs) ||
		!candidate.Transports.valid() ||
		!candidate.Policy.valid() {
		return ErrInvalidProductionProfileV2
	}
	return nil
}

func (candidate ProductionTransportsV2) valid() bool {
	if candidate.Primary != QUIC ||
		len(candidate.Fallbacks) != 2 ||
		candidate.Fallbacks[0] != WSS ||
		candidate.Fallbacks[1] != TCP ||
		len(candidate.Endpoints) != 3 {
		return false
	}
	expected := [...]Transport{QUIC, WSS, TCP}
	seenPorts := make(map[uint16]bool, len(expected))
	serverName := ""
	for index, endpoint := range candidate.Endpoints {
		if endpoint.Transport != expected[index] {
			return false
		}
		normalized, ok := normalizeProductionEndpointV2(endpoint)
		if !ok || seenPorts[normalized.Port] {
			return false
		}
		if index == 0 {
			serverName = normalized.ServerName
		} else if normalized.ServerName != serverName {
			return false
		}
		seenPorts[normalized.Port] = true
	}
	return true
}

func (candidate ProductionPolicyV2) valid() bool {
	return candidate.ConnectTimeoutSeconds >= 1 &&
		candidate.ConnectTimeoutSeconds <= 300 &&
		candidate.HealthIntervalSeconds >= 1 &&
		candidate.HealthIntervalSeconds <= 300 &&
		candidate.FallbackThreshold >= 1 &&
		candidate.FallbackThreshold <= 20
}

func (candidate ProductionProfileV2) Endpoint(transport Transport) (NormalizedProductionEndpointV2, error) {
	for _, endpoint := range candidate.Transports.Endpoints {
		if endpoint.Transport == transport {
			normalized, ok := normalizeProductionEndpointV2(endpoint)
			if !ok {
				return NormalizedProductionEndpointV2{}, ErrInvalidProductionProfileV2
			}
			return normalized, nil
		}
	}
	return NormalizedProductionEndpointV2{}, ErrInvalidProductionProfileV2
}

func (candidate ProductionProfileV2) ServerName() (string, error) {
	if err := candidate.Validate(); err != nil {
		return "", err
	}
	endpoint, err := candidate.Endpoint(QUIC)
	if err != nil {
		return "", err
	}
	return endpoint.ServerName, nil
}

func normalizeProductionEndpointV2(endpoint ProductionEndpointV2) (NormalizedProductionEndpointV2, bool) {
	parsed, err := url.Parse(endpoint.URL)
	if err != nil ||
		parsed.User != nil ||
		parsed.Opaque != "" ||
		parsed.RawPath != "" ||
		parsed.RawQuery != "" ||
		parsed.ForceQuery ||
		parsed.Fragment != "" ||
		parsed.RawFragment != "" ||
		parsed.Hostname() == "" ||
		!validProductionServerName(parsed.Hostname()) ||
		parsed.Port() == "" ||
		parsed.Host != parsed.Hostname()+":"+parsed.Port() ||
		parsed.String() != endpoint.URL {
		return NormalizedProductionEndpointV2{}, false
	}
	parsedPort, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil ||
		parsedPort < 1024 ||
		strconv.FormatUint(parsedPort, 10) != parsed.Port() {
		return NormalizedProductionEndpointV2{}, false
	}
	switch endpoint.Transport {
	case QUIC:
		if parsed.Scheme != "https" || parsed.Path != "" {
			return NormalizedProductionEndpointV2{}, false
		}
	case WSS:
		if parsed.Scheme != "wss" || parsed.Path != ProductionWSSPath {
			return NormalizedProductionEndpointV2{}, false
		}
	case TCP:
		if parsed.Scheme != "tcp" || parsed.Path != "" {
			return NormalizedProductionEndpointV2{}, false
		}
	default:
		return NormalizedProductionEndpointV2{}, false
	}
	return NormalizedProductionEndpointV2{
		Transport:  endpoint.Transport,
		URL:        endpoint.URL,
		Address:    parsed.Host,
		ServerName: parsed.Hostname(),
		Port:       uint16(parsedPort),
	}, true
}

func validProductionControlPlane(value string) bool {
	if value == "" ||
		len(value) > 2048 ||
		!productionControlPlaneLexicallyValid(value) {
		return false
	}
	authority := strings.TrimPrefix(value, "https://")
	if separator := strings.IndexByte(authority, '/'); separator >= 0 {
		authority = authority[:separator]
	}
	if strings.ContainsAny(authority, "[]") || strings.Count(authority, ":") > 1 {
		return false
	}
	host := authority
	if candidateHost, port, hasPort := strings.Cut(authority, ":"); hasPort {
		host = candidateHost
		parsedPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil ||
			parsedPort == 0 ||
			strconv.FormatUint(parsedPort, 10) != port {
			return false
		}
	}
	labels := strings.Split(host, ".")
	return validProductionServerName(host) &&
		strings.IndexFunc(labels[len(labels)-1], func(character rune) bool {
			return character >= 'a' && character <= 'z'
		}) >= 0
}

func productionControlPlaneLexicallyValid(value string) bool {
	const prefix = "https://"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	remainder := strings.TrimPrefix(value, prefix)
	authority, path, hasPath := strings.Cut(remainder, "/")
	if authority == "" || strings.Contains(authority, "@") {
		return false
	}
	for _, octet := range []byte(value) {
		if octet < 0x20 || octet > 0x7e || octet == '%' || octet == '\\' || octet == '?' || octet == '#' {
			return false
		}
	}
	for _, octet := range []byte(authority) {
		if !productionControlAuthorityCharacter(octet) {
			return false
		}
	}
	if hasPath {
		for _, octet := range []byte(path) {
			if !productionControlPathCharacter(octet) {
				return false
			}
		}
	}
	return true
}

func productionControlAuthorityCharacter(octet byte) bool {
	return isProductionASCIIAlphaNumeric(octet) ||
		strings.ContainsRune("-._~!$&'()*+,;=:[]", rune(octet))
}

func productionControlPathCharacter(octet byte) bool {
	return isProductionASCIIAlphaNumeric(octet) ||
		strings.ContainsRune("-._~!$&'()*+,;=:@/", rune(octet))
}

func isProductionASCIIAlphaNumeric(octet byte) bool {
	return octet >= 'a' && octet <= 'z' ||
		octet >= 'A' && octet <= 'Z' ||
		octet >= '0' && octet <= '9'
}

func validProductionIdentityRef(value string) bool {
	const prefix = "keychain:"
	return strings.HasPrefix(value, prefix) &&
		len(value) <= len(prefix)+128 &&
		validID(strings.TrimPrefix(value, prefix))
}

func validProductionDisplayName(value string) bool {
	return value != "" &&
		utf8.ValidString(value) &&
		utf8.RuneCountInString(value) <= 128 &&
		strings.TrimSpace(value) == value
}

func validProductionServerName(value string) bool {
	if value == "" ||
		len(value) > 253 ||
		strings.TrimSpace(value) != value ||
		value != strings.ToLower(value) ||
		strings.HasSuffix(value, ".") ||
		productionNumericDotOnly(value) {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
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

func decodeProductionPublicKey(value string) ([]byte, bool) {
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
	// WireGuard public keys are canonical X25519 u-coordinates. RFC 7748
	// masks this bit during multiplication, so accepting it would create a
	// second textual identity for the same point.
	if !canonicalProductionX25519Coordinate(decoded) {
		clear(decoded)
		return nil, false
	}
	validationScalar := [curve25519.ScalarSize]byte{9}
	shared, err := curve25519.X25519(validationScalar[:], decoded)
	clear(validationScalar[:])
	clear(shared)
	if err != nil {
		clear(decoded)
		return nil, false
	}
	for _, octet := range decoded {
		if octet != 0 {
			return decoded, true
		}
	}
	clear(decoded)
	return nil, false
}

func canonicalProductionX25519Coordinate(decoded []byte) bool {
	if len(decoded) != curve25519.PointSize {
		return false
	}
	for index := len(decoded) - 1; index >= 0; index-- {
		switch {
		case decoded[index] < productionX25519FieldPrime[index]:
			return true
		case decoded[index] > productionX25519FieldPrime[index]:
			return false
		}
	}
	return false
}

func productionHostPrefixes(values []string) ([]netip.Prefix, map[bool]bool, bool) {
	if len(values) == 0 || len(values) > 2 {
		return nil, nil, false
	}
	prefixes := make([]netip.Prefix, 0, len(values))
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
			!validProductionTunnelAddress(prefix.Addr()) ||
			seen[prefix] ||
			families[prefix.Addr().Is4()] {
			return nil, nil, false
		}
		seen[prefix] = true
		families[prefix.Addr().Is4()] = true
		prefixes = append(prefixes, prefix)
	}
	return prefixes, families, true
}

func productionPrivatePrefixes(values []string) ([]netip.Prefix, map[bool]bool, bool) {
	if len(values) == 0 || len(values) > MaxProductionProfileV2PrivateCIDRs {
		return nil, nil, false
	}
	prefixes := make([]netip.Prefix, 0, len(values))
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
			!validProductionPrivatePrefix(prefix) ||
			seen[prefix] {
			return nil, nil, false
		}
		textBytes += len(value)
		if textBytes > MaxProductionProfileV2CIDRTextBytes {
			return nil, nil, false
		}
		for _, existing := range prefixes {
			if prefix.Overlaps(existing) {
				return nil, nil, false
			}
		}
		seen[prefix] = true
		families[prefix.Addr().Is4()] = true
		prefixes = append(prefixes, prefix)
	}
	return prefixes, families, true
}

func validProductionTunnelAddress(value netip.Addr) bool {
	return value.IsValid() &&
		!value.Is4In6() &&
		value.Zone() == "" &&
		value.IsPrivate() &&
		!value.IsUnspecified() &&
		!value.IsMulticast() &&
		!value.IsLoopback() &&
		!value.IsLinkLocalUnicast()
}

func validProductionPrivatePrefix(value netip.Prefix) bool {
	if !value.IsValid() ||
		value.Addr().Is4In6() ||
		value.Addr().Zone() != "" ||
		value != value.Masked() {
		return false
	}
	for _, allowed := range productionPrivateRouteAllowlist {
		if value.Addr().BitLen() == allowed.Addr().BitLen() &&
			value.Bits() >= allowed.Bits() &&
			allowed.Contains(value.Addr()) {
			return true
		}
	}
	return false
}

func productionPrefixSetsOverlap(left, right []netip.Prefix) bool {
	for _, leftPrefix := range left {
		for _, rightPrefix := range right {
			if leftPrefix.Overlaps(rightPrefix) {
				return true
			}
		}
	}
	return false
}

func sameProductionFamilies(left, right map[bool]bool) bool {
	return left[true] == right[true] && left[false] == right[false]
}

func productionNumericDotOnly(value string) bool {
	for _, character := range value {
		if character != '.' && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func uniqueProductionProfileV2JSONKeys(encoded []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if !consumeUniqueProductionProfileV2JSONValue(decoder, 1) {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func exactProductionProfileV2JSONKeys(encoded []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return false
	}
	root, ok := exactProductionProfileV2Object(decoded, []string{
		"schema_version",
		"carrier_auth_version",
		"profile_id",
		"control_plane",
		"identity_ref",
		"site",
		"tunnel",
		"transports",
		"policy",
	})
	if !ok {
		return false
	}
	if _, ok := exactProductionProfileV2Object(root["site"], []string{
		"id",
		"display_name",
		"private_cidrs",
	}); !ok {
		return false
	}
	if _, ok := exactProductionProfileV2Object(root["tunnel"], []string{
		"local_addresses",
		"local_public_key",
		"peer_public_key",
		"keepalive_seconds",
	}); !ok {
		return false
	}
	transports, ok := exactProductionProfileV2Object(root["transports"], []string{
		"primary",
		"fallbacks",
		"endpoints",
	})
	if !ok {
		return false
	}
	if _, ok := exactProductionProfileV2Object(root["policy"], []string{
		"connect_timeout_seconds",
		"health_interval_seconds",
		"fallback_threshold",
	}); !ok {
		return false
	}
	endpoints, ok := transports["endpoints"].([]any)
	if !ok {
		return false
	}
	for _, endpoint := range endpoints {
		if _, ok := exactProductionProfileV2Object(endpoint, []string{
			"transport",
			"url",
		}); !ok {
			return false
		}
	}
	return true
}

func exactProductionProfileV2Object(value any, expected []string) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(expected) {
		return nil, false
	}
	for _, key := range expected {
		if _, exists := object[key]; !exists {
			return nil, false
		}
	}
	return object, true
}

func validProductionProfileV2JSONStringScalars(encoded []byte) bool {
	inString := false
	for index := 0; index < len(encoded); index++ {
		switch encoded[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			index++
			if index >= len(encoded) {
				return false
			}
			if encoded[index] != 'u' {
				continue
			}
			codePoint, ok := productionProfileV2JSONHex4(encoded, index+1)
			if !ok {
				return false
			}
			index += 4
			switch {
			case codePoint >= 0xD800 && codePoint <= 0xDBFF:
				if index+6 >= len(encoded) ||
					encoded[index+1] != '\\' ||
					encoded[index+2] != 'u' {
					return false
				}
				lowSurrogate, lowOK := productionProfileV2JSONHex4(encoded, index+3)
				if !lowOK || lowSurrogate < 0xDC00 || lowSurrogate > 0xDFFF {
					return false
				}
				index += 6
			case codePoint >= 0xDC00 && codePoint <= 0xDFFF:
				return false
			}
		}
	}
	return !inString
}

func productionProfileV2JSONHex4(encoded []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(encoded) {
		return 0, false
	}
	var result uint16
	for _, character := range encoded[start : start+4] {
		result <<= 4
		switch {
		case character >= '0' && character <= '9':
			result |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			result |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			result |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}

func consumeUniqueProductionProfileV2JSONValue(decoder *json.Decoder, depth int) bool {
	if depth > MaxProductionProfileV2JSONDepth {
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
			if !consumeUniqueProductionProfileV2JSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, closingErr := decoder.Token()
		return closingErr == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !consumeUniqueProductionProfileV2JSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, closingErr := decoder.Token()
		return closingErr == nil && closing == json.Delim(']')
	default:
		return false
	}
}
