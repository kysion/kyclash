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
	backend, err := userspace.NewLab(clientPrivate, cluster.Roots(), netip.MustParseAddrPort(ProbeAddress), "instance.cluster")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	networkProfile := &profile.Profile{
		Site:   profile.Site{PrivateCIDRs: []string{"10.88.0.2/32"}},
		Tunnel: profile.Tunnel{LocalAddresses: []string{"10.88.0.1/32"}, PeerPublicKey: cluster.PeerPublicKey(), KeepaliveSeconds: 5},
	}
	if _, err := backend.Prepare(context.Background(), networkProfile, "request.prepare"); err != nil {
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

func TestClusterCarriesBreakBeforeMakeAcrossAllCarriers(t *testing.T) {
	clientPrivate, clientPublic, err := keyPair()
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := StartCluster(context.Background(), clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	backend, err := userspace.NewLab(clientPrivate, cluster.Roots(), netip.MustParseAddrPort(ProbeAddress), "instance.cluster")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	networkProfile := &profile.Profile{
		Site:   profile.Site{PrivateCIDRs: []string{"10.88.0.2/32"}},
		Tunnel: profile.Tunnel{LocalAddresses: []string{"10.88.0.1/32"}, PeerPublicKey: cluster.PeerPublicKey(), KeepaliveSeconds: 5},
	}
	endpoints := cluster.Endpoints()
	networkProfile.Transports.Endpoints = endpoints
	if _, err := backend.Prepare(context.Background(), networkProfile, "request.prepare"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, transport := range []profile.Transport{profile.QUIC, profile.WSS, profile.TCP} {
		endpoint, err := networkProfile.Endpoint(transport)
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.Connect(ctx, transport, endpoint); err != nil {
			t.Fatalf("%s connect: %v", transport, err)
		}
		health, err := backend.Health(ctx)
		if err != nil || !health.Reachable {
			t.Fatalf("%s health: %#v %v", transport, health, err)
		}
		if err := backend.Disconnect(ctx); err != nil {
			t.Fatalf("%s disconnect: %v", transport, err)
		}
	}
	if err := backend.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestClusterCarriesProductionBackendHealthAcrossAllCarriers(t *testing.T) {
	clientPrivate, clientPublic, err := keyPair()
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := StartCluster(context.Background(), clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	backend, err := userspace.New(clientPrivate, cluster.Roots(), "instance.production-health")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	networkProfile := &profile.Profile{
		Site:   profile.Site{PrivateCIDRs: []string{"10.88.0.2/32"}},
		Tunnel: profile.Tunnel{LocalAddresses: []string{"10.88.0.1/32"}, PeerPublicKey: cluster.PeerPublicKey(), KeepaliveSeconds: 5},
	}
	networkProfile.Transports.Endpoints = cluster.Endpoints()
	if _, err := backend.Prepare(context.Background(), networkProfile, "request.prepare"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, transport := range []profile.Transport{profile.QUIC, profile.WSS, profile.TCP} {
		endpoint, err := networkProfile.Endpoint(transport)
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.Connect(ctx, transport, endpoint); err != nil {
			t.Fatalf("%s connect: %v", transport, err)
		}
		if err := cluster.WaitReady(ctx, transport); err != nil {
			t.Fatalf("%s ready: %v", transport, err)
		}
		health, err := backend.Health(ctx)
		if err != nil || !health.Reachable || health.LossPercent != 0 {
			t.Fatalf("%s production health: %#v %v", transport, health, err)
		}
		if err := backend.Disconnect(ctx); err != nil {
			t.Fatalf("%s disconnect: %v", transport, err)
		}
	}
	if err := backend.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestProductionBackendHealthDetectsAbruptLoopbackCarrierFailure(t *testing.T) {
	clientPrivate, clientPublic, err := keyPair()
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := StartCluster(context.Background(), clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	backend, err := userspace.New(clientPrivate, cluster.Roots(), "instance.production-failure")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	networkProfile := &profile.Profile{
		Site:   profile.Site{PrivateCIDRs: []string{"10.88.0.2/32"}},
		Tunnel: profile.Tunnel{LocalAddresses: []string{"10.88.0.1/32"}, PeerPublicKey: cluster.PeerPublicKey(), KeepaliveSeconds: 5},
	}
	networkProfile.Transports.Endpoints = cluster.Endpoints()
	if _, err := backend.Prepare(context.Background(), networkProfile, "request.prepare"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint, err := networkProfile.Endpoint(profile.TCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Connect(ctx, profile.TCP, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := cluster.WaitReady(ctx, profile.TCP); err != nil {
		t.Fatal(err)
	}
	if health, err := backend.Health(ctx); err != nil || !health.Reachable {
		t.Fatalf("initial live health failed: %#v %v", health, err)
	}
	if err := cluster.servers[profile.TCP].Close(); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	health, err := backend.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.Reachable || health.LossPercent != 100 {
		t.Fatalf("abrupt carrier failure was not reported: %#v", health)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("post-connect failure detection exceeded bound: %v", elapsed)
	}
}
