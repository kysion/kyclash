package vmexternalpeerlab

import (
	"crypto/ed25519"
	"crypto/sha256"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
)

// ValidateCourierExchange validates the complete signed public-only exchange
// in its one legal order: run ticket, the signature over the already
// published client bundle, then the peer bundle. Expected VM facts and the
// eight build artifacts come only from root-pinned configuration.
func ValidateCourierExchange(
	runID string,
	now time.Time,
	publicKey ed25519.PublicKey,
	config externalpeer.PeerSupervisorConfig,
	ticketExpectation externalpeer.RunTicketExpectation,
	clientFiles []externalpeer.CourierFile,
	clientManifest []byte,
	input ClientCourierInput,
) ([]externalpeer.CourierFile, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if len(publicKey) != ed25519.PublicKeySize || config.Validate() != nil ||
		ticketExpectation.Validate() != nil || len(clientManifest) == 0 {
		return nil, externalpeer.ErrInvalidCourierMessage
	}
	clientFacts, err := config.Client.CourierFacts()
	if err != nil {
		return nil, err
	}
	peerFacts, err := config.Peer.CourierFacts()
	if err != nil {
		return nil, err
	}
	if _, err := externalpeer.DecodeTransferManifest(
		clientManifest, runID, externalpeer.CourierClientToPeer, clientFiles,
	); err != nil {
		return nil, err
	}
	ticketFiles, err := ticketExpectation.FileTable()
	if err != nil {
		return nil, err
	}
	verifier, err := externalpeer.NewCourierVerifier(publicKey)
	if err != nil {
		return nil, err
	}
	zero := [sha256.Size]byte{}
	if _, err := verifier.Accept(input.RunTicket, externalpeer.CourierExpectation{
		Kind: externalpeer.CourierRunTicket, Sequence: 0, RunID: runID, Now: now,
		Source: clientFacts, Destination: peerFacts, TicketHash: zero, ManifestHash: zero,
		Files: ticketFiles,
	}); err != nil {
		return nil, err
	}
	ticketHash, err := externalpeer.CourierTicketHash(input.RunTicket)
	if err != nil {
		return nil, err
	}
	clientManifestHash := sha256.Sum256(clientManifest)
	if _, err := verifier.Accept(input.ClientEnvelope, externalpeer.CourierExpectation{
		Kind: externalpeer.CourierClientToPeer, Sequence: 1, RunID: runID, Now: now,
		Source: clientFacts, Destination: peerFacts, TicketHash: ticketHash,
		ManifestHash: clientManifestHash, Files: clientFiles,
	}); err != nil {
		return nil, err
	}
	peerPayloads := [][]byte{
		input.PeerArtifacts.Descriptor,
		input.PeerArtifacts.CADER,
		input.PeerArtifacts.ServerCertificateDER,
		input.PeerArtifacts.ClientCertificateDER,
		input.PeerArtifacts.OverlayServerPublicKey,
		input.PeerArtifacts.SystemSSHHostPublicKey,
	}
	peerPayloadFiles := make([]externalpeer.CourierFile, 0, len(peerPayloads))
	for index, payload := range peerPayloads {
		file, err := externalpeer.NewCourierFile(externalpeer.PeerArtifactNames[index], payload)
		if err != nil {
			return nil, err
		}
		peerPayloadFiles = append(peerPayloadFiles, file)
	}
	if _, err := externalpeer.DecodeTransferManifest(
		input.PeerArtifacts.TransferManifest,
		runID,
		externalpeer.CourierPeerToClient,
		peerPayloadFiles,
	); err != nil {
		return nil, err
	}
	manifestFile, err := externalpeer.NewCourierFile(
		externalpeer.PeerArtifactNames[len(externalpeer.PeerArtifactNames)-1],
		input.PeerArtifacts.TransferManifest,
	)
	if err != nil {
		return nil, err
	}
	peerFiles := append(peerPayloadFiles, manifestFile)
	peerManifestHash := sha256.Sum256(input.PeerArtifacts.TransferManifest)
	if _, err := verifier.Accept(input.PeerEnvelope, externalpeer.CourierExpectation{
		Kind: externalpeer.CourierPeerToClient, Sequence: 2, RunID: runID, Now: now,
		Source: peerFacts, Destination: clientFacts, TicketHash: ticketHash,
		ManifestHash: peerManifestHash, Files: peerFiles,
	}); err != nil {
		return nil, err
	}
	return peerFiles, nil
}
