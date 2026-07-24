package vmexternalpeerlab

import (
	"encoding/base64"
	"errors"
	"net/netip"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

// ProfileFromValidatedPeerDescriptor constructs the only profile accepted by
// the external-peer backend. The descriptor must already have passed
// externalpeer.DecodePeerPublicDescriptor with the run's exact artifacts and
// VM facts. This function adds no endpoint, route, or policy authority.
func ProfileFromValidatedPeerDescriptor(value externalpeer.PeerPublicDescriptor) (*profile.Profile, error) {
	peerKey, err := base64.StdEncoding.Strict().DecodeString(value.PeerWireGuardPublicKey)
	if err != nil || len(peerKey) != 32 {
		clear(peerKey)
		return nil, errors.New("invalid validated peer key")
	}
	clear(peerKey)
	if value.RunID == "" || value.PrivateEchoIPv4 != externalpeer.InnerPeerIPv4 ||
		value.PrivateEchoPort != externalpeer.PrivateEchoPort ||
		value.InnerClientIPv4 != externalpeer.InnerClientIPv4 ||
		value.InnerPeerIPv4 != externalpeer.InnerPeerIPv4 ||
		value.OverlaySSHAddress != OverlaySSH || value.SystemSSHProxyAddress != SystemSSH ||
		value.BindInterface != externalpeer.BindInterface || len(value.Endpoints) != 3 {
		return nil, errors.New("validated peer descriptor is outside the fixed profile")
	}
	peerUnderlay, err := netip.ParseAddr(value.PeerEn0PrivateIPv4)
	if err != nil || !peerUnderlay.Is4() || !peerUnderlay.IsPrivate() || peerUnderlay.IsLoopback() ||
		CoveringPrefix().Contains(peerUnderlay) {
		return nil, errors.New("validated peer underlay is outside the fixed profile")
	}
	candidate := &profile.Profile{
		SchemaVersion: profile.SchemaVersion,
		ProfileID:     ProfileID,
		ControlPlane:  "https://127.0.0.1/vm-external-peer-lab",
		IdentityRef:   "keychain:net.kysion.kyclash.test.vm-external-peer-lab",
		Site: profile.Site{
			ID: SiteID, DisplayName: "KyClash external peer VM lab",
			PrivateCIDRs: []string{PrivateCIDR},
		},
		Tunnel: profile.Tunnel{
			LocalAddresses: []string{ClientCIDR}, PeerPublicKey: value.PeerWireGuardPublicKey,
			KeepaliveSeconds: 5,
		},
		Transports: profile.Transports{
			Primary: profile.QUIC, Fallbacks: []profile.Transport{profile.WSS, profile.TCP},
			Endpoints: append([]profile.Endpoint(nil), value.Endpoints...),
		},
		Policy: profile.Policy{
			ConnectTimeoutSeconds: 5, HealthIntervalSeconds: 1, FallbackThreshold: 1,
		},
	}
	if err := candidate.Validate(); err != nil {
		return nil, err
	}
	for _, transport := range [...]profile.Transport{profile.QUIC, profile.WSS, profile.TCP} {
		endpoint, err := candidate.Endpoint(transport)
		if err != nil || endpoint.ServerName != peerUnderlay.String() {
			return nil, errors.New("validated endpoint does not bind the peer underlay")
		}
	}
	return candidate, nil
}
