package ipc

import (
	"encoding/json"
	"net/netip"
	"net/url"
)

type profile struct {
	SchemaVersion uint8  `json:"schema_version"`
	ProfileID     string `json:"profile_id"`
	ControlPlane  string `json:"control_plane"`
	IdentityRef   string `json:"identity_ref"`
	Site          struct {
		ID           string   `json:"id"`
		DisplayName  string   `json:"display_name"`
		PrivateCIDRs []string `json:"private_cidrs"`
	} `json:"site"`
	Tunnel struct {
		LocalAddresses   []string `json:"local_addresses"`
		PeerPublicKey    string   `json:"peer_public_key"`
		KeepaliveSeconds uint16   `json:"keepalive_seconds"`
	} `json:"tunnel"`
	Transports struct {
		Primary   string   `json:"primary"`
		Fallbacks []string `json:"fallbacks"`
		Endpoints []struct {
			Transport string `json:"transport"`
			URL       string `json:"url"`
		} `json:"endpoints"`
	} `json:"transports"`
	Policy struct {
		ConnectTimeoutSeconds uint16 `json:"connect_timeout_seconds"`
		HealthIntervalSeconds uint16 `json:"health_interval_seconds"`
		FallbackThreshold     uint8  `json:"fallback_threshold"`
	} `json:"policy"`
}

type session struct {
	profile         *profile
	tunnelPrepared  bool
	activeTransport string
}

func newSession() *session {
	return &session{}
}

func (current *session) status() Status {
	state := "disconnected"
	if current.tunnelPrepared {
		state = "preparing_tunnel"
	}
	if current.activeTransport == "quic" {
		state = "connected_primary"
	} else if current.activeTransport != "" {
		state = "degraded_fallback"
	}
	var profileID *string
	if current.profile != nil {
		value := current.profile.ProfileID
		profileID = &value
	}
	var transport *string
	if current.activeTransport != "" {
		value := current.activeTransport
		transport = &value
	}
	return Status{State: state, ActiveProfileID: profileID, ActiveTransport: transport}
}

func decodeProfile(data json.RawMessage) (*profile, bool) {
	var decoded profile
	if !decodeData(data, &decoded) || !decoded.valid() {
		return nil, false
	}
	return &decoded, true
}

func (candidate profile) valid() bool {
	controlPlane, controlErr := url.Parse(candidate.ControlPlane)
	if candidate.SchemaVersion != 1 || !validProfileID(candidate.ProfileID) || controlErr != nil || controlPlane.Scheme != "https" || controlPlane.Host == "" {
		return false
	}
	if candidate.IdentityRef == "" || candidate.Site.ID == "" || candidate.Site.DisplayName == "" || candidate.Tunnel.PeerPublicKey == "" {
		return false
	}
	if !validPrefixes(candidate.Site.PrivateCIDRs) || !validPrefixes(candidate.Tunnel.LocalAddresses) {
		return false
	}
	if candidate.Transports.Primary != "quic" || len(candidate.Transports.Endpoints) == 0 || candidate.Policy.ConnectTimeoutSeconds == 0 || candidate.Policy.HealthIntervalSeconds == 0 || candidate.Policy.FallbackThreshold == 0 {
		return false
	}
	configured := map[string]bool{"quic": true}
	for _, fallback := range candidate.Transports.Fallbacks {
		if fallback != "wss" && fallback != "tcp" || configured[fallback] {
			return false
		}
		configured[fallback] = true
	}
	seenEndpoints := make(map[string]bool)
	for _, endpoint := range candidate.Transports.Endpoints {
		parsed, err := url.Parse(endpoint.URL)
		if err != nil || !configured[endpoint.Transport] || seenEndpoints[endpoint.Transport] || !endpointScheme(endpoint.Transport, parsed.Scheme) || parsed.Host == "" || parsed.User != nil {
			return false
		}
		seenEndpoints[endpoint.Transport] = true
	}
	for transport := range configured {
		if !seenEndpoints[transport] {
			return false
		}
	}
	return true
}

func validProfileID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') && (index == 0 || character != '.' && character != '_' && character != ':' && character != '-') {
			return false
		}
	}
	return true
}

func validPrefixes(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[netip.Prefix]bool)
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || seen[prefix] {
			return false
		}
		seen[prefix] = true
	}
	return true
}

func endpointScheme(transport, scheme string) bool {
	switch transport {
	case "quic":
		return scheme == "https" || scheme == "quic"
	case "wss":
		return scheme == "wss"
	case "tcp":
		return scheme == "tcp"
	default:
		return false
	}
}
