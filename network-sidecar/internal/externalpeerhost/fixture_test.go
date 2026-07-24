package externalpeerhost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"golang.org/x/crypto/ssh"
)

const (
	hostTestRunID      = "external-peer-host-courier-test-0001"
	hostTestClientUUID = "11111111-1111-4111-8111-111111111111"
	hostTestPeerUUID   = "22222222-2222-4222-8222-222222222222"
	hostTestClientMAC  = "02:00:00:00:00:11"
	hostTestPeerMAC    = "02:00:00:00:00:22"
)

var (
	hostTestClientIP = netip.MustParseAddr("192.168.64.11")
	hostTestPeerIP   = netip.MustParseAddr("192.168.64.22")
)

type hostTransactionFixture struct {
	now                    time.Time
	input                  InitialTransactionInput
	peer                   externalpeer.PeerPublicArtifacts
	client                 *externalpeer.ClientIdentity
	peerID                 *externalpeer.PeerIdentity
	configRaw              []byte
	ticketRaw              []byte
	clientManagementPublic []byte
	peerManagementPublic   []byte
}

func newHostTransactionFixture(t *testing.T) hostTransactionFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := now.Add(30 * time.Minute)
	clientIdentity, err := externalpeer.NewClientIdentity(hostTestRunID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clientIdentity.Clear)
	clientWGPublic := bytes.Repeat([]byte{0x31}, 32)
	clientDescriptor, clientArtifacts, err := clientIdentity.PublicArtifacts(
		externalpeer.ClientDescriptorConfig{
			RunID: hostTestRunID, ExpiresAt: expiresAt,
			VirtualMacModel: "VirtualMac2,1",
			PlatformUUID:    hostTestClientUUID,
			ClientIPv4:      hostTestClientIP, ClientMAC: hostTestClientMAC,
			WireGuardPublicKey: clientWGPublic,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	clientFiles := mustCourierFiles(t, externalpeer.ClientArtifactNames[:], [][]byte{
		clientArtifacts.Descriptor,
		clientArtifacts.TLSClientCSRDER,
		clientArtifacts.OverlayClientPublicKey,
	})
	clientManifest, err := externalpeer.EncodeTransferManifest(
		hostTestRunID,
		externalpeer.CourierClientToPeer,
		clientFiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, systemHostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(systemHostPrivate) })
	systemHostSigner, err := ssh.NewSignerFromKey(systemHostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	peerIdentity, err := externalpeer.NewPeerIdentity(
		now,
		expiresAt,
		hostTestRunID,
		hostTestPeerIP,
		clientArtifacts.TLSClientCSRDER,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peerIdentity.Clear)
	_, peerArtifacts, err := peerIdentity.PublicArtifacts(
		externalpeer.PeerDescriptorConfig{
			RunID: hostTestRunID, IssuedAt: now, ExpiresAt: expiresAt,
			ClientPlatformUUID: hostTestClientUUID,
			PeerPlatformUUID:   hostTestPeerUUID,
			ClientIPv4:         hostTestClientIP, PeerIPv4: hostTestPeerIP,
			ClientMAC: hostTestClientMAC, PeerMAC: hostTestPeerMAC,
			ClientWireGuardPublicKey: clientWGPublic,
			ClientOverlayPublicKey:   clientArtifacts.OverlayClientPublicKey,
			Endpoints: []profile.Endpoint{
				{Transport: profile.QUIC, URL: "https://192.168.64.22:22001"},
				{Transport: profile.WSS, URL: "wss://192.168.64.22:22002/kynp"},
				{Transport: profile.TCP, URL: "tcp://192.168.64.22:22003"},
			},
			SystemSSHHostPublicKey: systemHostSigner.PublicKey().Marshal(),
		},
		clientDescriptor,
	)
	if err != nil {
		t.Fatal(err)
	}
	peerFiles := mustCourierFiles(
		t,
		externalpeer.PeerArtifactNames[:len(externalpeer.PeerArtifactNames)-1],
		[][]byte{
			peerArtifacts.Descriptor,
			peerArtifacts.CADER,
			peerArtifacts.ServerCertificateDER,
			peerArtifacts.ClientCertificateDER,
			peerArtifacts.OverlayServerPublicKey,
			peerArtifacts.SystemSSHHostPublicKey,
		},
	)
	peerManifest, err := externalpeer.EncodeTransferManifest(
		hostTestRunID,
		externalpeer.CourierPeerToClient,
		peerFiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	peerArtifacts.TransferManifest = peerManifest
	config := externalpeer.PeerSupervisorConfig{
		SchemaVersion: externalpeer.SchemaVersion,
		ConsoleUID:    501, ConsoleGID: 20, PeerChildUID: 502, PeerChildGID: 20,
		Client: externalpeer.SupervisorVMConfig{
			Role: "client", VMName: externalpeer.ClientVMName,
			PlatformUUID:       hostTestClientUUID,
			SSHHostFingerprint: ssh.FingerprintSHA256(systemHostSigner.PublicKey()),
			MAC:                hostTestClientMAC, IPv4: hostTestClientIP.String(),
		},
		Peer: externalpeer.SupervisorVMConfig{
			Role: "peer", VMName: externalpeer.PeerVMName,
			PlatformUUID:       hostTestPeerUUID,
			SSHHostFingerprint: ssh.FingerprintSHA256(systemHostSigner.PublicKey()),
			MAC:                hostTestPeerMAC, IPv4: hostTestPeerIP.String(),
		},
	}
	// Management host keys are role-separated in workspace tests even though
	// the public peer descriptor uses its own independent system host key.
	_, clientManagementPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(clientManagementPrivate) })
	clientManagementSigner, err := ssh.NewSignerFromKey(clientManagementPrivate)
	if err != nil {
		t.Fatal(err)
	}
	config.Client.SSHHostFingerprint = ssh.FingerprintSHA256(
		clientManagementSigner.PublicKey(),
	)
	_, peerManagementPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(peerManagementPrivate) })
	peerManagementSigner, err := ssh.NewSignerFromKey(peerManagementPrivate)
	if err != nil {
		t.Fatal(err)
	}
	config.Peer.SSHHostFingerprint = ssh.FingerprintSHA256(
		peerManagementSigner.PublicKey(),
	)
	ticket := externalpeer.RunTicketExpectation{
		SchemaVersion: externalpeer.SchemaVersion,
		Files: make(
			[]externalpeer.ArtifactDigest,
			0,
			len(externalpeer.RunTicketArtifactNames),
		),
	}
	for index, name := range externalpeer.RunTicketArtifactNames {
		payload := bytes.Repeat([]byte{byte(index + 1)}, index+1)
		ticket.Files = append(ticket.Files, externalpeer.ArtifactDigest{
			Name: name, Length: uint64(len(payload)),
			SHA256: externalpeer.HashHex(payload),
		})
	}
	configRaw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ticketRaw, err := json.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	return hostTransactionFixture{
		now: now,
		input: InitialTransactionInput{
			Config: config, TicketExpectation: ticket,
			ClientArtifacts: clientArtifacts, ClientManifest: clientManifest,
		},
		peer:      peerArtifacts,
		client:    clientIdentity,
		peerID:    peerIdentity,
		configRaw: append(configRaw, '\n'),
		ticketRaw: append(ticketRaw, '\n'),
		clientManagementPublic: append(
			[]byte(nil),
			clientManagementSigner.PublicKey().Marshal()...,
		),
		peerManagementPublic: append(
			[]byte(nil),
			peerManagementSigner.PublicKey().Marshal()...,
		),
	}
}

func mustCourierFiles(
	t *testing.T,
	names []string,
	payloads [][]byte,
) []externalpeer.CourierFile {
	t.Helper()
	if len(names) != len(payloads) {
		t.Fatal("courier fixture length mismatch")
	}
	files := make([]externalpeer.CourierFile, 0, len(names))
	for index, name := range names {
		file, err := externalpeer.NewCourierFile(name, payloads[index])
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	return files
}
