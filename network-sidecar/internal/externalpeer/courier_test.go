package externalpeer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

func TestCourierExactCodecSignatureOrderAndReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	now := time.Now().UTC().Truncate(time.Second)
	clientFacts := testCourierFacts(t, "client")
	peerFacts := testCourierFacts(t, "peer")
	ticketFiles := testCourierFiles(t, RunTicketArtifactNames[:])
	ticket := CourierMessage{
		Kind:        CourierRunTicket,
		Sequence:    0,
		RunID:       testRunID,
		IssuedAt:    uint64(now.Unix()),
		ExpiresAt:   uint64(now.Add(90 * time.Second).Unix()),
		Nonce:       mustNonce(t),
		Source:      clientFacts,
		Destination: peerFacts,
		Files:       ticketFiles,
	}
	ticketEnvelope, err := SignCourierMessage(ticket, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ticketHash, err := CourierTicketHash(ticketEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewCourierVerifier(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	acceptedTicket, err := verifier.Accept(ticketEnvelope, CourierExpectation{
		Kind:        CourierRunTicket,
		Sequence:    0,
		RunID:       testRunID,
		Now:         now,
		Source:      clientFacts,
		Destination: peerFacts,
		Files:       ticketFiles,
	})
	if err != nil || acceptedTicket.Kind != CourierRunTicket {
		t.Fatalf("ticket refused: %v", err)
	}
	if _, err := verifier.Accept(ticketEnvelope, CourierExpectation{
		Kind:        CourierRunTicket,
		Sequence:    0,
		RunID:       testRunID,
		Now:         now,
		Source:      clientFacts,
		Destination: peerFacts,
		Files:       ticketFiles,
	}); err == nil {
		t.Fatal("ticket replay was accepted")
	}

	clientFiles := testCourierFiles(t, ClientArtifactNames[:])
	clientManifest, err := EncodeTransferManifest(
		testRunID,
		CourierClientToPeer,
		clientFiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientMessage := CourierMessage{
		Kind:         CourierClientToPeer,
		Sequence:     1,
		RunID:        testRunID,
		IssuedAt:     uint64(now.Unix()),
		ExpiresAt:    uint64(now.Add(90 * time.Second).Unix()),
		Nonce:        mustNonce(t),
		Source:       clientFacts,
		Destination:  peerFacts,
		TicketHash:   ticketHash,
		ManifestHash: sha256.Sum256(clientManifest),
		Files:        clientFiles,
	}
	clientEnvelope, err := SignCourierMessage(clientMessage, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Accept(clientEnvelope, CourierExpectation{
		Kind:         CourierClientToPeer,
		Sequence:     1,
		RunID:        testRunID,
		Now:          now,
		Source:       clientFacts,
		Destination:  peerFacts,
		TicketHash:   ticketHash,
		ManifestHash: sha256.Sum256(clientManifest),
		Files:        clientFiles,
	}); err != nil {
		t.Fatal(err)
	}

	peerPayloadFiles := testCourierFiles(t, PeerArtifactNames[:len(PeerArtifactNames)-1])
	peerManifest, err := EncodeTransferManifest(
		testRunID,
		CourierPeerToClient,
		peerPayloadFiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	peerManifestFile, err := NewCourierFile(
		PeerArtifactNames[len(PeerArtifactNames)-1],
		peerManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	peerFiles := append(peerPayloadFiles, peerManifestFile)
	peerMessage := CourierMessage{
		Kind:         CourierPeerToClient,
		Sequence:     2,
		RunID:        testRunID,
		IssuedAt:     uint64(now.Unix()),
		ExpiresAt:    uint64(now.Add(90 * time.Second).Unix()),
		Nonce:        mustNonce(t),
		Source:       peerFacts,
		Destination:  clientFacts,
		TicketHash:   ticketHash,
		ManifestHash: sha256.Sum256(peerManifest),
		Files:        peerFiles,
	}
	peerEnvelope, err := SignCourierMessage(peerMessage, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Accept(peerEnvelope, CourierExpectation{
		Kind:         CourierPeerToClient,
		Sequence:     2,
		RunID:        testRunID,
		Now:          now,
		Source:       peerFacts,
		Destination:  clientFacts,
		TicketHash:   ticketHash,
		ManifestHash: sha256.Sum256(peerManifest),
		Files:        peerFiles,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCourierRejectsTamperRoleSwapStaleAndPostCancel(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	now := time.Now().UTC().Truncate(time.Second)
	clientFacts := testCourierFacts(t, "client")
	peerFacts := testCourierFacts(t, "peer")
	files := testCourierFiles(t, RunTicketArtifactNames[:])
	ticket := CourierMessage{
		Kind:        CourierRunTicket,
		Sequence:    0,
		RunID:       testRunID,
		IssuedAt:    uint64(now.Unix()),
		ExpiresAt:   uint64(now.Add(90 * time.Second).Unix()),
		Nonce:       mustNonce(t),
		Source:      clientFacts,
		Destination: peerFacts,
		Files:       files,
	}
	envelope, err := SignCourierMessage(ticket, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), envelope...)
	tampered[len(CourierDomain)+1] ^= 1
	if _, err := DecodeAndVerifyCourierMessage(tampered, publicKey, CourierExpectation{
		Kind:        CourierRunTicket,
		Sequence:    0,
		RunID:       testRunID,
		Now:         now,
		Source:      clientFacts,
		Destination: peerFacts,
		Files:       files,
	}); err == nil {
		t.Fatal("tampered signed bytes were accepted")
	}
	if _, err := DecodeAndVerifyCourierMessage(envelope, publicKey, CourierExpectation{
		Kind:        CourierRunTicket,
		Sequence:    0,
		RunID:       testRunID,
		Now:         now,
		Source:      peerFacts,
		Destination: clientFacts,
		Files:       files,
	}); err == nil {
		t.Fatal("role swap was accepted")
	}
	if _, err := DecodeAndVerifyCourierMessage(envelope, publicKey, CourierExpectation{
		Kind:        CourierRunTicket,
		Sequence:    0,
		RunID:       testRunID,
		Now:         now.Add(5 * time.Minute),
		Source:      clientFacts,
		Destination: peerFacts,
		Files:       files,
	}); err == nil {
		t.Fatal("stale ticket was accepted")
	}

	ticketHash, err := CourierTicketHash(envelope)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := NewCourierVerifier(publicKey)
	if _, err := verifier.Accept(envelope, CourierExpectation{
		Kind: CourierRunTicket, Sequence: 0, RunID: testRunID, Now: now,
		Source: clientFacts, Destination: peerFacts, Files: files,
	}); err != nil {
		t.Fatal(err)
	}
	clientFiles := testCourierFiles(t, ClientArtifactNames[:])
	manifest, _ := EncodeTransferManifest(testRunID, CourierClientToPeer, clientFiles)
	manifestHash := sha256.Sum256(manifest)
	clientMessage := CourierMessage{
		Kind: CourierClientToPeer, Sequence: 1, RunID: testRunID,
		IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(90 * time.Second).Unix()),
		Nonce: mustNonce(t), Source: clientFacts, Destination: peerFacts,
		TicketHash: ticketHash, ManifestHash: manifestHash, Files: clientFiles,
	}
	clientEnvelope, _ := SignCourierMessage(clientMessage, privateKey)
	if _, err := verifier.Accept(clientEnvelope, CourierExpectation{
		Kind: CourierClientToPeer, Sequence: 1, RunID: testRunID, Now: now,
		Source: clientFacts, Destination: peerFacts, TicketHash: ticketHash,
		ManifestHash: manifestHash, Files: clientFiles,
	}); err != nil {
		t.Fatal(err)
	}
	lateCancel := CourierMessage{
		Kind: CourierCancel, Sequence: 3, RunID: testRunID,
		IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(100 * time.Second).Unix()),
		Nonce: mustNonce(t), Source: clientFacts, Destination: peerFacts,
		TicketHash: ticketHash,
	}
	lateCancelEnvelope, _ := SignCourierMessage(lateCancel, privateKey)
	if _, err := verifier.Accept(lateCancelEnvelope, CourierExpectation{
		Kind: CourierCancel, Sequence: 3, RunID: testRunID, Now: now,
		Source: clientFacts, Destination: peerFacts, TicketHash: ticketHash,
	}); err == nil {
		t.Fatal("cancel expiring after its run ticket was accepted")
	}
	cancel := CourierMessage{
		Kind: CourierCancel, Sequence: 3, RunID: testRunID,
		IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(90 * time.Second).Unix()),
		Nonce: mustNonce(t), Source: clientFacts, Destination: peerFacts,
		TicketHash: ticketHash,
	}
	cancelEnvelope, _ := SignCourierMessage(cancel, privateKey)
	if _, err := verifier.Accept(cancelEnvelope, CourierExpectation{
		Kind: CourierCancel, Sequence: 3, RunID: testRunID, Now: now,
		Source: clientFacts, Destination: peerFacts, TicketHash: ticketHash,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Accept(cancelEnvelope, CourierExpectation{
		Kind: CourierCancel, Sequence: 3, RunID: testRunID, Now: now,
		Source: clientFacts, Destination: peerFacts, TicketHash: ticketHash,
	}); err == nil {
		t.Fatal("post-cancel input was accepted")
	}
}

func testCourierFacts(t *testing.T, role string) CourierVMFacts {
	t.Helper()
	if role == "client" {
		value, err := NewCourierVMFacts(
			"client",
			ClientVMName,
			testClientUUID,
			"SHA256:client-host-key",
			testClientMAC,
			testClientIP,
		)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	value, err := NewCourierVMFacts(
		"peer",
		PeerVMName,
		testPeerUUID,
		"SHA256:peer-host-key",
		testPeerMAC,
		testPeerIP,
	)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testCourierFiles(t *testing.T, names []string) []CourierFile {
	t.Helper()
	files := make([]CourierFile, 0, len(names))
	for index, name := range names {
		file, err := NewCourierFile(name, []byte{byte(index + 1)})
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	return files
}

func mustNonce(t *testing.T) [32]byte {
	t.Helper()
	value, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
