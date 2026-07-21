// Package profile owns the strict, reusable KyClash network profile contract.
package profile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

const (
	SchemaVersion = 1
	TunnelMTU     = 1_420
)

var ErrInvalid = errors.New("invalid network profile")

type Transport string

const (
	QUIC Transport = "quic"
	WSS  Transport = "wss"
	TCP  Transport = "tcp"
)

type Profile struct {
	SchemaVersion uint8      `json:"schema_version"`
	ProfileID     string     `json:"profile_id"`
	ControlPlane  string     `json:"control_plane"`
	IdentityRef   string     `json:"identity_ref"`
	Site          Site       `json:"site"`
	Tunnel        Tunnel     `json:"tunnel"`
	Transports    Transports `json:"transports"`
	Policy        Policy     `json:"policy"`
}

type Site struct {
	ID           string   `json:"id"`
	DisplayName  string   `json:"display_name"`
	PrivateCIDRs []string `json:"private_cidrs"`
}

type Tunnel struct {
	LocalAddresses   []string `json:"local_addresses"`
	PeerPublicKey    string   `json:"peer_public_key"`
	KeepaliveSeconds uint16   `json:"keepalive_seconds"`
}

type Transports struct {
	Primary   Transport   `json:"primary"`
	Fallbacks []Transport `json:"fallbacks"`
	Endpoints []Endpoint  `json:"endpoints"`
}

type Endpoint struct {
	Transport Transport `json:"transport"`
	URL       string    `json:"url"`
}

type Policy struct {
	ConnectTimeoutSeconds uint16 `json:"connect_timeout_seconds"`
	HealthIntervalSeconds uint16 `json:"health_interval_seconds"`
	FallbackThreshold     uint8  `json:"fallback_threshold"`
}

type NormalizedEndpoint struct {
	Transport  Transport
	URL        string
	Address    string
	ServerName string
}

func (candidate Profile) String() string {
	return fmt.Sprintf("Profile{SchemaVersion:%d ProfileID:%q SiteID:%q Tunnel:<redacted> Endpoints:<redacted>}", candidate.SchemaVersion, candidate.ProfileID, candidate.Site.ID)
}

func Decode(data []byte) (*Profile, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded Profile
	if err := decoder.Decode(&decoded); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrInvalid
	}
	if err := decoded.Validate(); err != nil {
		return nil, err
	}
	return &decoded, nil
}

func (candidate Profile) Validate() error {
	controlPlane, err := url.Parse(candidate.ControlPlane)
	if candidate.SchemaVersion != SchemaVersion || !validID(candidate.ProfileID) || !validID(candidate.Site.ID) || !validIdentityRef(candidate.IdentityRef) || err != nil || controlPlane.Scheme != "https" || controlPlane.Host == "" || controlPlane.User != nil || controlPlane.Fragment != "" {
		return ErrInvalid
	}
	if candidate.Site.DisplayName == "" || candidate.Tunnel.KeepaliveSeconds == 0 || !validWireGuardKey(candidate.Tunnel.PeerPublicKey) || !validPrefixes(candidate.Site.PrivateCIDRs, true) || !validPrefixes(candidate.Tunnel.LocalAddresses, false) {
		return ErrInvalid
	}
	if candidate.Transports.Primary != QUIC || len(candidate.Transports.Endpoints) == 0 || candidate.Policy.ConnectTimeoutSeconds == 0 || candidate.Policy.HealthIntervalSeconds == 0 || candidate.Policy.FallbackThreshold == 0 {
		return ErrInvalid
	}
	configured := map[Transport]bool{QUIC: true}
	for _, fallback := range candidate.Transports.Fallbacks {
		if fallback != WSS && fallback != TCP || configured[fallback] {
			return ErrInvalid
		}
		configured[fallback] = true
	}
	seen := make(map[Transport]bool)
	for _, endpoint := range candidate.Transports.Endpoints {
		if !configured[endpoint.Transport] || seen[endpoint.Transport] {
			return ErrInvalid
		}
		if _, err := normalize(endpoint); err != nil {
			return err
		}
		seen[endpoint.Transport] = true
	}
	for transport := range configured {
		if !seen[transport] {
			return ErrInvalid
		}
	}
	return nil
}

func (candidate Profile) Endpoint(transport Transport) (NormalizedEndpoint, error) {
	for _, endpoint := range candidate.Transports.Endpoints {
		if endpoint.Transport == transport {
			return normalize(endpoint)
		}
	}
	return NormalizedEndpoint{}, ErrInvalid
}

func (candidate Profile) HasTransport(transport Transport) bool {
	if transport == candidate.Transports.Primary {
		return true
	}
	for _, fallback := range candidate.Transports.Fallbacks {
		if transport == fallback {
			return true
		}
	}
	return false
}

func (candidate Profile) PeerKeyBytes() ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(candidate.Tunnel.PeerPublicKey)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return nil, ErrInvalid
	}
	return decoded, nil
}

func normalize(endpoint Endpoint) (NormalizedEndpoint, error) {
	parsed, err := url.Parse(endpoint.URL)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Hostname() == "" {
		return NormalizedEndpoint{}, ErrInvalid
	}
	expectedScheme := map[Transport]string{QUIC: "https", WSS: "wss", TCP: "tcp"}[endpoint.Transport]
	if parsed.Scheme != expectedScheme {
		return NormalizedEndpoint{}, ErrInvalid
	}
	port := parsed.Port()
	if port == "" {
		if endpoint.Transport == QUIC || endpoint.Transport == WSS {
			port = "443"
		} else {
			return NormalizedEndpoint{}, ErrInvalid
		}
	}
	if endpoint.Transport != WSS && parsed.Path != "" && parsed.Path != "/" {
		return NormalizedEndpoint{}, ErrInvalid
	}
	return NormalizedEndpoint{
		Transport:  endpoint.Transport,
		URL:        parsed.String(),
		Address:    net.JoinHostPort(parsed.Hostname(), port),
		ServerName: parsed.Hostname(),
	}, nil
}

func validID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if !isAlphaNumeric(character) && (index == 0 || !strings.ContainsRune("._:-", character)) {
			return false
		}
	}
	return true
}

func validIdentityRef(value string) bool {
	return strings.HasPrefix(value, "keychain:") && validID(strings.TrimPrefix(value, "keychain:"))
}

func validPrefixes(values []string, requireNetwork bool) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[netip.Prefix]bool)
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || seen[prefix] || requireNetwork && prefix != prefix.Masked() {
			return false
		}
		seen[prefix] = true
	}
	return true
}

func validWireGuardKey(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	valid := err == nil && len(decoded) == 32
	clear(decoded)
	return valid
}

func isAlphaNumeric(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}
