package productionpeer

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

func validPairProductionProfileV2(t *testing.T) profile.ProductionProfileV2 {
	t.Helper()
	encoded, err := os.ReadFile("../../../schemas/fixtures/network-production-v2.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := profile.DecodeProductionProfileV2(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	return *decoded
}

func TestProductionProfileV2PairsWithTheExactLinuxPeerFixture(t *testing.T) {
	productionProfile := validPairProductionProfileV2(t)
	peerConfig := validConfig(t)
	paired, err := PairProductionProfileV2(&productionProfile, &peerConfig)
	if err != nil {
		t.Fatal(err)
	}
	if paired == nil {
		t.Fatal("pair validator returned a nil capability")
	}
	implementation := reflect.TypeOf(paired)
	if implementation.Kind() != reflect.Pointer ||
		implementation.Elem().Name() != "PairedProfileV2" ||
		implementation.Elem().PkgPath() != "github.com/kysion/kyclash/network-sidecar/internal/productionpeer" {
		t.Fatalf("pair capability is not backed by the opaque package type: %v", implementation)
	}
	for index := 0; index < implementation.Elem().NumField(); index++ {
		if implementation.Elem().Field(index).IsExported() {
			t.Fatalf("paired capability exposes externally constructible field %q", implementation.Elem().Field(index).Name)
		}
	}

	snapshot, err := paired.ProductionProfile()
	if err != nil {
		t.Fatal(err)
	}
	peerSnapshot, err := paired.ProductionPeerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Tunnel.PeerPublicKey != peerSnapshot.WireGuard.ServerPublicKeyBase64 ||
		snapshot.Tunnel.LocalPublicKey != peerSnapshot.WireGuard.Clients[0].PublicKeyBase64 ||
		!reflect.DeepEqual(snapshot.Tunnel.LocalAddresses, peerSnapshot.WireGuard.Clients[0].TunnelAddresses) ||
		!reflect.DeepEqual(snapshot.Site.PrivateCIDRs, peerSnapshot.Forwarding.PrivateCIDRs) {
		t.Fatal("sealed pair snapshot lost a locked cross-machine field")
	}
	serverName, err := snapshot.ServerName()
	if err != nil || serverName != peerSnapshot.TLS.ServerName {
		t.Fatalf("server-name pair drift: %q %v", serverName, err)
	}
	if peerSnapshot.WireGuard.MTU != profile.ProductionTunnelMTU ||
		TunnelMTU != profile.ProductionTunnelMTU ||
		QUICALPN != profile.ProductionQUICALPN ||
		WSSPath != profile.ProductionWSSPath {
		t.Fatal("MTU, ALPN, or WSS-path constant drift")
	}
	for index, transport := range []profile.Transport{profile.QUIC, profile.WSS, profile.TCP} {
		if snapshot.Transports.Endpoints[index].Transport != transport ||
			peerSnapshot.Listeners[index].Transport != transport ||
			snapshot.Transports.Endpoints[index].URL != peerSnapshot.Listeners[index].URL {
			t.Fatalf("ordered endpoint %d does not match the Linux Peer fixture", index)
		}
	}
}

func TestProductionProfileV2PairRejectsEveryCrossMachineMutation(t *testing.T) {
	type pairMutation struct {
		mutate            func(*profile.ProductionProfileV2, *Config)
		inputsRemainValid bool
	}
	validKey := func(octet byte) string {
		return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{octet}, 32))
	}
	tests := map[string]pairMutation{
		"profile-auth-version": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				productionProfile.CarrierAuthVersion = 2
			},
		},
		"peer-auth-version": {
			mutate: func(_ *profile.ProductionProfileV2, peerConfig *Config) {
				peerConfig.CarrierAuthVersion = 2
			},
		},
		"server-public-key": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				productionProfile.Tunnel.PeerPublicKey = validKey(0x33)
			},
			inputsRemainValid: true,
		},
		"client-public-key": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				productionProfile.Tunnel.LocalPublicKey = validKey(0x44)
			},
			inputsRemainValid: true,
		},
		"local-address-value": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				productionProfile.Tunnel.LocalAddresses = []string{"10.255.255.3/32", "fd00:255::3/128"}
			},
			inputsRemainValid: true,
		},
		"local-address-order": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				productionProfile.Tunnel.LocalAddresses[0], productionProfile.Tunnel.LocalAddresses[1] =
					productionProfile.Tunnel.LocalAddresses[1], productionProfile.Tunnel.LocalAddresses[0]
			},
			inputsRemainValid: true,
		},
		"server-name": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				for index := range productionProfile.Transports.Endpoints {
					productionProfile.Transports.Endpoints[index].URL = strings.Replace(
						productionProfile.Transports.Endpoints[index].URL,
						"peer.example.invalid",
						"other.example.invalid",
						1,
					)
				}
			},
			inputsRemainValid: true,
		},
		"quic-url": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				productionProfile.Transports.Endpoints[0].URL = "https://peer.example.invalid:3443"
			},
			inputsRemainValid: true,
		},
		"wss-url": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				productionProfile.Transports.Endpoints[1].URL = "wss://peer.example.invalid:3444/kynp"
			},
			inputsRemainValid: true,
		},
		"tcp-url": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				productionProfile.Transports.Endpoints[2].URL = "tcp://peer.example.invalid:3445"
			},
			inputsRemainValid: true,
		},
		"private-cidr-value": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				productionProfile.Site.PrivateCIDRs[0] = "10.126.0.0/16"
			},
			inputsRemainValid: true,
		},
		"private-cidr-order": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				productionProfile.Site.PrivateCIDRs[0], productionProfile.Site.PrivateCIDRs[1] =
					productionProfile.Site.PrivateCIDRs[1], productionProfile.Site.PrivateCIDRs[0]
			},
			inputsRemainValid: true,
		},
		"transport-order": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				productionProfile.Transports.Endpoints[0], productionProfile.Transports.Endpoints[1] =
					productionProfile.Transports.Endpoints[1], productionProfile.Transports.Endpoints[0]
			},
		},
		"wss-path": {
			mutate: func(productionProfile *profile.ProductionProfileV2, _ *Config) {
				productionProfile.Transports.Endpoints[1].URL = "wss://peer.example.invalid:2444/other"
			},
		},
		"mtu": {
			mutate: func(_ *profile.ProductionProfileV2, peerConfig *Config) {
				peerConfig.WireGuard.MTU = profile.ProductionTunnelMTU - 1
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			productionProfile := validPairProductionProfileV2(t)
			peerConfig := validConfig(t)
			test.mutate(&productionProfile, &peerConfig)
			if test.inputsRemainValid {
				if err := productionProfile.Validate(); err != nil {
					t.Fatalf("profile mutation was not independently valid: %v", err)
				}
				if err := peerConfig.Validate(); err != nil {
					t.Fatalf("peer fixture unexpectedly became invalid: %v", err)
				}
			}
			if paired, err := PairProductionProfileV2(&productionProfile, &peerConfig); paired != nil ||
				!errors.Is(err, ErrProductionProfileV2PairMismatch) {
				t.Fatalf("pair mutation was accepted: %#v %v", paired, err)
			}
		})
	}
}

func TestProductionProfileV2PairRejectsNilAndV1Inputs(t *testing.T) {
	productionProfile := validPairProductionProfileV2(t)
	peerConfig := validConfig(t)
	for name, invoke := range map[string]func() (*PairedProfileV2, error){
		"nil-profile": func() (*PairedProfileV2, error) {
			return PairProductionProfileV2(nil, &peerConfig)
		},
		"nil-peer": func() (*PairedProfileV2, error) {
			return PairProductionProfileV2(&productionProfile, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			paired, err := invoke()
			if paired != nil || !errors.Is(err, ErrProductionProfileV2PairMismatch) {
				t.Fatalf("nil pair input was accepted: %#v %v", paired, err)
			}
		})
	}
	v1, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profile.DecodeProductionProfileV2(bytes.NewReader(v1)); !errors.Is(err, profile.ErrInvalidProductionProfileV2) {
		t.Fatalf("production pair input decoder accepted v1: %v", err)
	}
	for name, candidate := range map[string]*PairedProfileV2{
		"nil-handle":  nil,
		"zero-handle": {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := candidate.ProductionProfile(); !errors.Is(err, ErrProductionProfileV2PairMismatch) {
				t.Fatalf("externally constructible invalid handle exposed a profile: %v", err)
			}
			if _, err := candidate.ProductionPeerConfig(); !errors.Is(err, ErrProductionProfileV2PairMismatch) {
				t.Fatalf("externally constructible invalid handle exposed a peer config: %v", err)
			}
		})
	}
}

func TestPairedProductionProfileV2SnapshotsCannotBeMutatedThroughInputsOrGetters(t *testing.T) {
	productionProfile := validPairProductionProfileV2(t)
	peerConfig := validConfig(t)
	paired, err := PairProductionProfileV2(&productionProfile, &peerConfig)
	if err != nil {
		t.Fatal(err)
	}
	expectedProfileAddress := productionProfile.Tunnel.LocalAddresses[0]
	expectedPeerAddress := peerConfig.WireGuard.Clients[0].TunnelAddresses[0]
	productionProfile.Tunnel.LocalAddresses[0] = "10.255.255.99/32"
	peerConfig.WireGuard.Clients[0].TunnelAddresses[0] = "10.255.255.98/32"
	firstProfileSnapshot, err := paired.ProductionProfile()
	if err != nil {
		t.Fatal(err)
	}
	firstPeerSnapshot, err := paired.ProductionPeerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if firstProfileSnapshot.Tunnel.LocalAddresses[0] != expectedProfileAddress ||
		firstPeerSnapshot.WireGuard.Clients[0].TunnelAddresses[0] != expectedPeerAddress {
		t.Fatal("paired capability retained mutable input aliases")
	}
	firstProfileSnapshot.Tunnel.LocalAddresses[0] = "10.255.255.97/32"
	firstPeerSnapshot.WireGuard.Clients[0].TunnelAddresses[0] = "10.255.255.96/32"
	secondProfileSnapshot, err := paired.ProductionProfile()
	if err != nil {
		t.Fatal(err)
	}
	secondPeerSnapshot, err := paired.ProductionPeerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if secondProfileSnapshot.Tunnel.LocalAddresses[0] != expectedProfileAddress ||
		secondPeerSnapshot.WireGuard.Clients[0].TunnelAddresses[0] != expectedPeerAddress {
		t.Fatal("paired capability exposed mutable snapshot aliases")
	}
}

func TestPairedProductionProfileV2AccessorsRevalidatePrivateState(t *testing.T) {
	productionProfile := validPairProductionProfileV2(t)
	peerConfig := validConfig(t)
	paired, err := PairProductionProfileV2(&productionProfile, &peerConfig)
	if err != nil {
		t.Fatal(err)
	}
	paired.state.peerConfig.WireGuard.MTU--
	if _, err := paired.ProductionProfile(); !errors.Is(err, ErrProductionProfileV2PairMismatch) {
		t.Fatalf("corrupted private pair state exposed a profile: %v", err)
	}
	if _, err := paired.ProductionPeerConfig(); !errors.Is(err, ErrProductionProfileV2PairMismatch) {
		t.Fatalf("corrupted private pair state exposed a peer config: %v", err)
	}
}
