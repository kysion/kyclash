package vmexternalpeerlab

import (
	"encoding/base64"
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

func validProfileDescriptor() externalpeer.PeerPublicDescriptor {
	return externalpeer.PeerPublicDescriptor{
		RunID:                  "run-12345678",
		BindInterface:          "en0",
		PeerEn0PrivateIPv4:     "192.168.77.12",
		PeerWireGuardPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		PrivateEchoIPv4:        "10.88.0.2",
		PrivateEchoPort:        8080,
		OverlaySSHAddress:      "10.88.0.2:22",
		SystemSSHProxyAddress:  "10.88.0.2:2222",
		InnerClientIPv4:        "10.88.0.1",
		InnerPeerIPv4:          "10.88.0.2",
		Endpoints: []profile.Endpoint{
			{Transport: profile.QUIC, URL: "https://192.168.77.12:31001"},
			{Transport: profile.WSS, URL: "wss://192.168.77.12:31002/kynp"},
			{Transport: profile.TCP, URL: "tcp://192.168.77.12:31003"},
		},
	}
}

func TestProfileFromValidatedPeerDescriptorIsFixed(t *testing.T) {
	value, err := ProfileFromValidatedPeerDescriptor(validProfileDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	if value.ProfileID != ProfileID || value.Site.ID != SiteID ||
		value.Site.PrivateCIDRs[0] != PrivateCIDR || value.Tunnel.LocalAddresses[0] != ClientCIDR ||
		value.Transports.Primary != profile.QUIC || value.Transports.Fallbacks[0] != profile.WSS ||
		value.Transports.Fallbacks[1] != profile.TCP {
		t.Fatalf("unexpected external profile: %#v", value)
	}
}

func TestProfileFromValidatedPeerDescriptorRejectsEndpointSubstitution(t *testing.T) {
	value := validProfileDescriptor()
	value.Endpoints[2].URL = "tcp://192.168.77.13:31003"
	if _, err := ProfileFromValidatedPeerDescriptor(value); err == nil {
		t.Fatal("accepted an endpoint on another peer")
	}
	value = validProfileDescriptor()
	value.PeerEn0PrivateIPv4 = "127.0.0.1"
	if _, err := ProfileFromValidatedPeerDescriptor(value); err == nil {
		t.Fatal("accepted a loopback external peer")
	}
}
