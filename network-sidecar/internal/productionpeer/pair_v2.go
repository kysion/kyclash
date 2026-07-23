package productionpeer

import (
	"errors"
	"slices"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

var ErrProductionProfileV2PairMismatch = errors.New("production profile v2 does not match production peer configuration")

// PairedProfileV2 is an opaque validated capability. A package-external caller
// can allocate only its invalid zero value; the private state required by every
// accessor is created solely by PairProductionProfileV2.
type PairedProfileV2 struct {
	state *pairedProfileV2State
}

type pairedProfileV2State struct {
	productionProfile profile.ProductionProfileV2
	peerConfig        Config
}

// PairProductionProfileV2 validates both public documents and returns a
// sealed immutable snapshot only when every locked cross-machine field agrees.
// It reads no credentials and performs no network or system operation.
func PairProductionProfileV2(
	productionProfile *profile.ProductionProfileV2,
	peerConfig *Config,
) (*PairedProfileV2, error) {
	if productionProfile == nil ||
		peerConfig == nil ||
		productionProfile.Validate() != nil ||
		peerConfig.Validate() != nil ||
		!productionPairFieldsMatch(productionProfile, peerConfig) {
		return nil, ErrProductionProfileV2PairMismatch
	}
	return &PairedProfileV2{
		state: &pairedProfileV2State{
			productionProfile: cloneProductionProfileV2(*productionProfile),
			peerConfig:        cloneProductionPeerConfigV2(*peerConfig),
		},
	}, nil
}

func (candidate *PairedProfileV2) ProductionProfile() (profile.ProductionProfileV2, error) {
	if !candidate.valid() {
		return profile.ProductionProfileV2{}, ErrProductionProfileV2PairMismatch
	}
	return cloneProductionProfileV2(candidate.state.productionProfile), nil
}

func (candidate *PairedProfileV2) ProductionPeerConfig() (Config, error) {
	if !candidate.valid() {
		return Config{}, ErrProductionProfileV2PairMismatch
	}
	return cloneProductionPeerConfigV2(candidate.state.peerConfig), nil
}

func (candidate *PairedProfileV2) valid() bool {
	return candidate != nil &&
		candidate.state != nil &&
		candidate.state.productionProfile.Validate() == nil &&
		candidate.state.peerConfig.Validate() == nil &&
		productionPairFieldsMatch(&candidate.state.productionProfile, &candidate.state.peerConfig)
}

func productionEndpointURLsMatch(
	productionProfile *profile.ProductionProfileV2,
	peerConfig *Config,
) bool {
	serverName, err := productionProfile.ServerName()
	if err != nil ||
		serverName != peerConfig.TLS.ServerName ||
		len(productionProfile.Transports.Endpoints) != 3 ||
		len(peerConfig.Listeners) != 3 {
		return false
	}
	expected := [...]profile.Transport{profile.QUIC, profile.WSS, profile.TCP}
	for index, transport := range expected {
		profileEndpoint := productionProfile.Transports.Endpoints[index]
		peerListener := peerConfig.Listeners[index]
		if profileEndpoint.Transport != transport ||
			peerListener.Transport != transport ||
			profileEndpoint.URL != peerListener.URL {
			return false
		}
	}
	return true
}

func productionPairFieldsMatch(
	productionProfile *profile.ProductionProfileV2,
	peerConfig *Config,
) bool {
	return productionProfile != nil &&
		peerConfig != nil &&
		productionProfile.SchemaVersion == profile.ProductionSchemaVersionV2 &&
		peerConfig.SchemaVersion == ConfigSchemaVersion &&
		productionProfile.CarrierAuthVersion == peerConfig.CarrierAuthVersion &&
		productionProfile.CarrierAuthVersion == profile.ProductionCarrierAuthVersionV1 &&
		productionProfile.Tunnel.PeerPublicKey == peerConfig.WireGuard.ServerPublicKeyBase64 &&
		len(peerConfig.WireGuard.Clients) == MaxAuthorizedClients &&
		productionProfile.Tunnel.LocalPublicKey == peerConfig.WireGuard.Clients[0].PublicKeyBase64 &&
		slices.Equal(productionProfile.Tunnel.LocalAddresses, peerConfig.WireGuard.Clients[0].TunnelAddresses) &&
		slices.Equal(productionProfile.Site.PrivateCIDRs, peerConfig.Forwarding.PrivateCIDRs) &&
		peerConfig.WireGuard.MTU == profile.ProductionTunnelMTU &&
		TunnelMTU == profile.ProductionTunnelMTU &&
		QUICALPN == profile.ProductionQUICALPN &&
		WSSPath == profile.ProductionWSSPath &&
		productionEndpointURLsMatch(productionProfile, peerConfig)
}

func cloneProductionProfileV2(candidate profile.ProductionProfileV2) profile.ProductionProfileV2 {
	candidate.Site.PrivateCIDRs = slices.Clone(candidate.Site.PrivateCIDRs)
	candidate.Tunnel.LocalAddresses = slices.Clone(candidate.Tunnel.LocalAddresses)
	candidate.Transports.Fallbacks = slices.Clone(candidate.Transports.Fallbacks)
	candidate.Transports.Endpoints = slices.Clone(candidate.Transports.Endpoints)
	return candidate
}

func cloneProductionPeerConfigV2(candidate Config) Config {
	candidate.WireGuard.ServerAddresses = slices.Clone(candidate.WireGuard.ServerAddresses)
	candidate.WireGuard.Clients = slices.Clone(candidate.WireGuard.Clients)
	for index := range candidate.WireGuard.Clients {
		candidate.WireGuard.Clients[index].TunnelAddresses = slices.Clone(
			candidate.WireGuard.Clients[index].TunnelAddresses,
		)
	}
	candidate.Listeners = slices.Clone(candidate.Listeners)
	candidate.Forwarding.PrivateCIDRs = slices.Clone(candidate.Forwarding.PrivateCIDRs)
	return candidate
}
