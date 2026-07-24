package labserver

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/userspace"
)

const clusterCleanupTimeout = 5 * time.Second

func TestClusterCarriesBackendHealthProbe(t *testing.T) {
	clientPrivate, clientPublic, err := keyPair()
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := StartCluster(context.Background(), clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClusterAndWait(t, cluster)
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
	ctx, cancel := context.WithTimeout(context.Background(), clusterSingleHealthTimeout)
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
	defer closeClusterAndWait(t, cluster)
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
	ctx, cancel := context.WithTimeout(context.Background(), clusterCarrierMatrixTimeout)
	defer cancel()
	for _, transport := range []profile.Transport{profile.QUIC, profile.WSS, profile.TCP} {
		endpoint, err := networkProfile.Endpoint(transport)
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.Connect(ctx, transport, endpoint); err != nil {
			t.Fatalf("%s connect: %v", transport, err)
		}
		if err := waitClusterReadyPreservingDone(ctx, cluster, transport); err != nil {
			t.Fatalf("%s ready: %v", transport, err)
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
	defer closeClusterAndWait(t, cluster)
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
	ctx, cancel := context.WithTimeout(context.Background(), clusterCarrierMatrixTimeout)
	defer cancel()
	for _, transport := range []profile.Transport{profile.QUIC, profile.WSS, profile.TCP} {
		endpoint, err := networkProfile.Endpoint(transport)
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.Connect(ctx, transport, endpoint); err != nil {
			t.Fatalf("%s connect: %v", transport, err)
		}
		if err := waitClusterReadyPreservingDone(ctx, cluster, transport); err != nil {
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
	defer closeClusterAndWait(t, cluster)
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
	ctx, cancel := context.WithTimeout(context.Background(), clusterFailureLifecycleTimeout)
	defer cancel()
	endpoint, err := networkProfile.Endpoint(profile.TCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Connect(ctx, profile.TCP, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := waitClusterReadyPreservingDone(ctx, cluster, profile.TCP); err != nil {
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
	if elapsed := time.Since(started); elapsed > clusterFailureObservationBound {
		t.Fatalf("post-connect failure detection exceeded bound: %v", elapsed)
	}
}

func closeClusterAndWait(t *testing.T, cluster *Cluster) {
	t.Helper()
	if err := cluster.Close(); err != nil {
		t.Errorf("close cluster: %v", err)
		return
	}
	timer := time.NewTimer(clusterCleanupTimeout)
	defer timer.Stop()
	quicDone := cluster.Done(profile.QUIC)
	wssDone := cluster.Done(profile.WSS)
	tcpDone := cluster.Done(profile.TCP)
	remaining := 3
	for remaining > 0 {
		select {
		case err := <-quicDone:
			quicDone = nil
			remaining--
			if err != nil {
				t.Errorf("%s cluster cleanup: %v", profile.QUIC, err)
			}
		case err := <-wssDone:
			wssDone = nil
			remaining--
			if err != nil {
				t.Errorf("%s cluster cleanup: %v", profile.WSS, err)
			}
		case err := <-tcpDone:
			tcpDone = nil
			remaining--
			if err != nil {
				t.Errorf("%s cluster cleanup: %v", profile.TCP, err)
			}
		case <-timer.C:
			t.Errorf(
				"cluster cleanup timed out: quic_pending=%t wss_pending=%t tcp_pending=%t",
				quicDone != nil,
				wssDone != nil,
				tcpDone != nil,
			)
			return
		}
	}
}

func waitClusterReadyPreservingDone(
	ctx context.Context,
	cluster *Cluster,
	transport profile.Transport,
) error {
	server := cluster.servers[transport]
	if server == nil {
		return ErrInvalid
	}
	select {
	case <-server.ready:
		return nil
	case err := <-server.done:
		// Server.Done is a one-value channel rather than a closed broadcast
		// signal. Preserve the terminal value for closeClusterAndWait so an
		// observed startup failure cannot hide cleanup evidence.
		server.done <- err
		if err == nil {
			return net.ErrClosed
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
