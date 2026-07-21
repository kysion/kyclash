package labserver

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/userspace"
)

func TestClusterCarriesBackendHealthProbe(t *testing.T) {
	clientPrivate, clientPublic, err := keyPair()
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := StartCluster(context.Background(), clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	backend, err := userspace.NewLab(clientPrivate, cluster.Roots(), netip.MustParseAddrPort(ProbeAddress))
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	networkProfile := &profile.Profile{
		Site:   profile.Site{PrivateCIDRs: []string{"10.88.0.2/32"}},
		Tunnel: profile.Tunnel{LocalAddresses: []string{"10.88.0.1/32"}, PeerPublicKey: cluster.PeerPublicKey(), KeepaliveSeconds: 5},
	}
	if err := backend.Prepare(context.Background(), networkProfile); err != nil {
		t.Fatal(err)
	}
	endpoint := cluster.Endpoints()[0]
	normalized := profile.NormalizedEndpoint{Transport: endpoint.Transport, URL: endpoint.URL}
	// Exercise the production normalizer instead of duplicating URL parsing.
	networkProfile.Transports.Endpoints = []profile.Endpoint{endpoint}
	if value, endpointErr := networkProfile.Endpoint(endpoint.Transport); endpointErr == nil {
		normalized = value
	} else {
		t.Fatal(endpointErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := backend.Connect(ctx, endpoint.Transport, normalized); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if err := backend.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
}
