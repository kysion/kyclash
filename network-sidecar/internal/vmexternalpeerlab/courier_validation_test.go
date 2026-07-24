package vmexternalpeerlab

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
)

func TestValidateCourierExchangeBindsTicketManifestsFactsAndOrder(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)

	const runID = "external-peer-validation-1"
	now := time.Now().UTC().Truncate(time.Second)
	config := testCourierSupervisorConfig()
	clientFacts, err := config.Client.CourierFacts()
	if err != nil {
		t.Fatal(err)
	}
	peerFacts, err := config.Peer.CourierFacts()
	if err != nil {
		t.Fatal(err)
	}

	ticketExpectation := externalpeer.RunTicketExpectation{
		SchemaVersion: externalpeer.SchemaVersion,
		Files:         make([]externalpeer.ArtifactDigest, 0, len(externalpeer.RunTicketArtifactNames)),
	}
	for index, name := range externalpeer.RunTicketArtifactNames {
		payload := []byte{byte(index + 1)}
		ticketExpectation.Files = append(ticketExpectation.Files, externalpeer.ArtifactDigest{
			Name: name, Length: uint64(len(payload)), SHA256: externalpeer.HashHex(payload),
		})
	}
	ticketFiles, err := ticketExpectation.FileTable()
	if err != nil {
		t.Fatal(err)
	}

	clientPayloads := [][]byte{{0x11}, {0x12}, {0x13}}
	clientFiles := makeCourierFiles(t, externalpeer.ClientArtifactNames[:], clientPayloads)
	clientManifest, err := externalpeer.EncodeTransferManifest(
		runID, externalpeer.CourierClientToPeer, clientFiles,
	)
	if err != nil {
		t.Fatal(err)
	}

	peerPayloads := [][]byte{{0x21}, {0x22}, {0x23}, {0x24}, {0x25}, {0x26}}
	peerPayloadFiles := makeCourierFiles(
		t, externalpeer.PeerArtifactNames[:len(externalpeer.PeerArtifactNames)-1], peerPayloads,
	)
	peerManifest, err := externalpeer.EncodeTransferManifest(
		runID, externalpeer.CourierPeerToClient, peerPayloadFiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	peerManifestFile, err := externalpeer.NewCourierFile(
		externalpeer.PeerArtifactNames[len(externalpeer.PeerArtifactNames)-1], peerManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	peerFiles := append(peerPayloadFiles, peerManifestFile)

	ticketEnvelope := signCourier(t, privateKey, externalpeer.CourierMessage{
		Kind: externalpeer.CourierRunTicket, Sequence: 0, RunID: runID,
		IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(90 * time.Second).Unix()),
		Nonce: mustCourierNonce(t), Source: clientFacts, Destination: peerFacts, Files: ticketFiles,
	})
	ticketHash, err := externalpeer.CourierTicketHash(ticketEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	clientEnvelope := signCourier(t, privateKey, externalpeer.CourierMessage{
		Kind: externalpeer.CourierClientToPeer, Sequence: 1, RunID: runID,
		IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(90 * time.Second).Unix()),
		Nonce: mustCourierNonce(t), Source: clientFacts, Destination: peerFacts,
		TicketHash: ticketHash, ManifestHash: sha256.Sum256(clientManifest), Files: clientFiles,
	})
	peerEnvelope := signCourier(t, privateKey, externalpeer.CourierMessage{
		Kind: externalpeer.CourierPeerToClient, Sequence: 2, RunID: runID,
		IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(90 * time.Second).Unix()),
		Nonce: mustCourierNonce(t), Source: peerFacts, Destination: clientFacts,
		TicketHash: ticketHash, ManifestHash: sha256.Sum256(peerManifest), Files: peerFiles,
	})
	input := ClientCourierInput{
		RunTicket: ticketEnvelope, ClientEnvelope: clientEnvelope, PeerEnvelope: peerEnvelope,
		PeerArtifacts: externalpeer.PeerPublicArtifacts{
			Descriptor: peerPayloads[0], CADER: peerPayloads[1],
			ServerCertificateDER: peerPayloads[2], ClientCertificateDER: peerPayloads[3],
			OverlayServerPublicKey: peerPayloads[4], SystemSSHHostPublicKey: peerPayloads[5],
			TransferManifest: peerManifest,
		},
	}

	validated, err := ValidateCourierExchange(
		runID, now, publicKey, config, ticketExpectation, clientFiles, clientManifest, input,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(validated) != len(externalpeer.PeerArtifactNames) {
		t.Fatalf("unexpected peer file count: %d", len(validated))
	}

	tampered := input
	tampered.PeerEnvelope = append([]byte(nil), input.PeerEnvelope...)
	tampered.PeerEnvelope[len(tampered.PeerEnvelope)-1] ^= 0x80
	if _, err := ValidateCourierExchange(
		runID, now, publicKey, config, ticketExpectation, clientFiles, clientManifest, tampered,
	); err == nil {
		t.Fatal("tampered peer envelope was accepted")
	}
}

func testCourierSupervisorConfig() externalpeer.PeerSupervisorConfig {
	return externalpeer.PeerSupervisorConfig{
		SchemaVersion: externalpeer.SchemaVersion,
		ConsoleUID:    501, ConsoleGID: 20, PeerChildUID: 502, PeerChildGID: 20,
		Client: externalpeer.SupervisorVMConfig{
			Role: "client", VMName: externalpeer.ClientVMName,
			PlatformUUID:       "11111111-1111-4111-8111-111111111111",
			SSHHostFingerprint: "SHA256:client-host-key",
			MAC:                "02:00:00:00:00:11", IPv4: "192.168.64.11",
		},
		Peer: externalpeer.SupervisorVMConfig{
			Role: "peer", VMName: externalpeer.PeerVMName,
			PlatformUUID:       "22222222-2222-4222-8222-222222222222",
			SSHHostFingerprint: "SHA256:peer-host-key",
			MAC:                "02:00:00:00:00:22", IPv4: "192.168.64.12",
		},
	}
}

func makeCourierFiles(t *testing.T, names []string, payloads [][]byte) []externalpeer.CourierFile {
	t.Helper()
	if len(names) != len(payloads) {
		t.Fatal("courier test fixture mismatch")
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

func mustCourierNonce(t *testing.T) [32]byte {
	t.Helper()
	nonce, err := externalpeer.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return nonce
}

func signCourier(t *testing.T, key ed25519.PrivateKey, message externalpeer.CourierMessage) []byte {
	t.Helper()
	envelope, err := externalpeer.SignCourierMessage(message, key)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
