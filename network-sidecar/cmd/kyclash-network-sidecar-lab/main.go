// kyclash-network-sidecar-lab is a networking-dev integration executable. It
// is never bundled with KyClash and cannot bind outside loopback.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"

	"github.com/kysion/kyclash/network-sidecar/internal/bootstrap"
	"github.com/kysion/kyclash/network-sidecar/internal/ipc"
	"github.com/kysion/kyclash/network-sidecar/internal/labserver"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/userspace"
	"golang.org/x/crypto/curve25519"
)

type labHandshake struct {
	ProtocolVersion uint8           `json:"protocol_version"`
	InstanceID      string          `json:"instance_id"`
	AuthProof       string          `json:"auth_proof"`
	LabProfile      profile.Profile `json:"lab_profile"`
	CancelEndpoint  string          `json:"cancel_endpoint"`
}

func run(arguments []string, stdin io.Reader, stdout io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("command-line arguments are not accepted")
	}
	reader := bufio.NewReaderSize(stdin, 64*1_024)
	config, err := bootstrap.DecodeLine(reader)
	if err != nil {
		return err
	}
	defer config.Clear()
	clientPublic, err := curve25519.X25519(config.PrivateKey, curve25519.Basepoint)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cluster, err := labserver.StartCluster(ctx, clientPublic)
	clear(clientPublic)
	if err != nil {
		return err
	}
	defer cluster.Close()
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer blackhole.Close()
	go discardPackets(ctx, blackhole)
	networkProfile := makeProfile(cluster)
	if err := networkProfile.Validate(); err != nil {
		return err
	}
	backend, err := userspace.NewLab(config.PrivateKey, cluster.Roots(), netip.MustParseAddrPort(labserver.ProbeAddress))
	if err != nil {
		return err
	}
	proof := bootstrap.AuthProof(config)
	response := labHandshake{ProtocolVersion: bootstrap.ProtocolVersion, InstanceID: config.InstanceID, AuthProof: proof, LabProfile: networkProfile, CancelEndpoint: "https://" + blackhole.LocalAddr().String()}
	config.Clear()
	if err := json.NewEncoder(stdout).Encode(response); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}
	return ipc.ServeWithBackend(reader, stdout, backend)
}

func discardPackets(ctx context.Context, connection net.PacketConn) {
	go func() { <-ctx.Done(); _ = connection.Close() }()
	buffer := make([]byte, 64*1_024)
	for {
		if _, _, err := connection.ReadFrom(buffer); err != nil {
			return
		}
	}
}

func makeProfile(cluster *labserver.Cluster) profile.Profile {
	return profile.Profile{
		SchemaVersion: profile.SchemaVersion,
		ProfileID:     "lab.actual-child",
		ControlPlane:  "https://127.0.0.1/control",
		IdentityRef:   "keychain:net.kysion.kyclash.test.actual-child",
		Site:          profile.Site{ID: "lab", DisplayName: "KyClash loopback lab", PrivateCIDRs: []string{"10.88.0.2/32"}},
		Tunnel:        profile.Tunnel{LocalAddresses: []string{"10.88.0.1/32"}, PeerPublicKey: cluster.PeerPublicKey(), KeepaliveSeconds: 5},
		Transports:    profile.Transports{Primary: profile.QUIC, Fallbacks: []profile.Transport{profile.WSS, profile.TCP}, Endpoints: cluster.Endpoints()},
		Policy:        profile.Policy{ConnectTimeoutSeconds: 5, HealthIntervalSeconds: 1, FallbackThreshold: 1},
	}
}

func execute(arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if err := run(arguments, stdin, stdout); err != nil {
		fmt.Fprintln(stderr, "KyClash network lab sidecar failed")
		return 1
	}
	return 0
}

func main() {
	os.Exit(execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
