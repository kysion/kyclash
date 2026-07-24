package externalpeerhost

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/netip"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
)

type InitialTransactionInput struct {
	Config            externalpeer.PeerSupervisorConfig
	TicketExpectation externalpeer.RunTicketExpectation
	ClientArtifacts   externalpeer.ClientPublicArtifacts
	ClientManifest    []byte
}

type SignedInitialTransaction struct {
	RunID        string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	RunTicket    []byte
	ClientToPeer []byte
}

type SignedPeerResponse struct {
	PeerToClient []byte
}

type SignedCancellation struct {
	Cancel []byte
}

type transactionBranch uint8

const (
	transactionAwaitingPeer transactionBranch = iota + 1
	transactionPeerSigned
	transactionCancelled
	transactionPeerSignedCancelled
)

type preparedInitial struct {
	runID             string
	clientFacts       externalpeer.CourierVMFacts
	peerFacts         externalpeer.CourierVMFacts
	ticketFiles       []externalpeer.CourierFile
	clientFiles       []externalpeer.CourierFile
	clientManifestSum [sha256.Size]byte
	clientDescriptor  externalpeer.ClientPublicDescriptor
	clientWGPublic    []byte
	clientMAC         string
	peerMAC           string
}

// TransactionSigner is a one-run state machine. It signs ticket+sequence 1
// first, then exactly one of a validated peer response (sequence 2) or a
// cancellation (sequence 3). It cannot pre-create both terminal branches.
type TransactionSigner struct {
	privateKey      ed25519.PrivateKey
	publicKey       ed25519.PublicKey
	prepared        preparedInitial
	initial         SignedInitialTransaction
	ticketHash      [sha256.Size]byte
	seenNonce       map[[32]byte]struct{}
	branch          transactionBranch
	clientArtifacts externalpeer.ClientPublicArtifacts
}

func NewTransactionSigner(
	input InitialTransactionInput,
	privateKey ed25519.PrivateKey,
	now time.Time,
	entropy io.Reader,
) (*TransactionSigner, SignedInitialTransaction, error) {
	if len(privateKey) != ed25519.PrivateKeySize || entropy == nil {
		return nil, SignedInitialTransaction{}, ErrInvalidHostTransaction
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	issuedAt := now.UTC().Truncate(time.Second)
	if issuedAt.Unix() <= 0 {
		return nil, SignedInitialTransaction{}, ErrInvalidHostTransaction
	}
	prepared, err := prepareInitialTransaction(input, issuedAt)
	if err != nil {
		return nil, SignedInitialTransaction{}, err
	}
	nonces, err := uniqueNonces(entropy, 2, nil)
	if err != nil {
		clear(prepared.clientWGPublic)
		return nil, SignedInitialTransaction{}, err
	}
	expiresAt := issuedAt.Add(externalpeer.MaxCourierLife)
	ticketEnvelope, err := externalpeer.SignCourierMessage(
		externalpeer.CourierMessage{
			Kind:        externalpeer.CourierRunTicket,
			Sequence:    0,
			RunID:       prepared.runID,
			IssuedAt:    uint64(issuedAt.Unix()),
			ExpiresAt:   uint64(expiresAt.Unix()),
			Nonce:       nonces[0],
			Source:      prepared.clientFacts,
			Destination: prepared.peerFacts,
			Files:       prepared.ticketFiles,
		},
		privateKey,
	)
	if err != nil {
		clear(prepared.clientWGPublic)
		return nil, SignedInitialTransaction{}, ErrInvalidHostTransaction
	}
	ticketHash, err := externalpeer.CourierTicketHash(ticketEnvelope)
	if err != nil {
		clear(prepared.clientWGPublic)
		clear(ticketEnvelope)
		return nil, SignedInitialTransaction{}, ErrInvalidHostTransaction
	}
	clientEnvelope, err := externalpeer.SignCourierMessage(
		externalpeer.CourierMessage{
			Kind:         externalpeer.CourierClientToPeer,
			Sequence:     1,
			RunID:        prepared.runID,
			IssuedAt:     uint64(issuedAt.Unix()),
			ExpiresAt:    uint64(expiresAt.Unix()),
			Nonce:        nonces[1],
			Source:       prepared.clientFacts,
			Destination:  prepared.peerFacts,
			TicketHash:   ticketHash,
			ManifestHash: prepared.clientManifestSum,
			Files:        prepared.clientFiles,
		},
		privateKey,
	)
	if err != nil {
		clear(prepared.clientWGPublic)
		clear(ticketEnvelope)
		return nil, SignedInitialTransaction{}, ErrInvalidHostTransaction
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		clear(prepared.clientWGPublic)
		clear(ticketEnvelope)
		clear(clientEnvelope)
		return nil, SignedInitialTransaction{}, ErrInvalidHostTransaction
	}
	initial := SignedInitialTransaction{
		RunID:        prepared.runID,
		IssuedAt:     issuedAt,
		ExpiresAt:    expiresAt,
		RunTicket:    ticketEnvelope,
		ClientToPeer: clientEnvelope,
	}
	signer := &TransactionSigner{
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		publicKey:  append(ed25519.PublicKey(nil), publicKey...),
		prepared:   prepared,
		initial:    cloneInitial(initial),
		ticketHash: ticketHash,
		seenNonce: map[[32]byte]struct{}{
			nonces[0]: {},
			nonces[1]: {},
		},
		branch: transactionAwaitingPeer,
		clientArtifacts: externalpeer.ClientPublicArtifacts{
			Descriptor:             append([]byte(nil), input.ClientArtifacts.Descriptor...),
			TLSClientCSRDER:        append([]byte(nil), input.ClientArtifacts.TLSClientCSRDER...),
			OverlayClientPublicKey: append([]byte(nil), input.ClientArtifacts.OverlayClientPublicKey...),
		},
	}
	if signer.verifyInitial(input, issuedAt) != nil {
		signer.Close()
		initial.Clear()
		return nil, SignedInitialTransaction{}, ErrInvalidHostTransaction
	}
	return signer, initial, nil
}

func (signer *TransactionSigner) SignPeerResponse(
	artifacts externalpeer.PeerPublicArtifacts,
	now time.Time,
	entropy io.Reader,
) (SignedPeerResponse, error) {
	if signer == nil || signer.branch != transactionAwaitingPeer ||
		entropy == nil || signer.ensureWithinTicket(now) != nil {
		return SignedPeerResponse{}, ErrInvalidHostTransaction
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	peerFiles, peerManifestSum, err := signer.validatePeerArtifacts(artifacts, now)
	if err != nil {
		return SignedPeerResponse{}, err
	}
	nonces, err := uniqueNonces(entropy, 1, signer.seenNonce)
	if err != nil {
		return SignedPeerResponse{}, err
	}
	issuedAt := now.UTC().Truncate(time.Second)
	envelope, err := externalpeer.SignCourierMessage(
		externalpeer.CourierMessage{
			Kind:         externalpeer.CourierPeerToClient,
			Sequence:     2,
			RunID:        signer.prepared.runID,
			IssuedAt:     uint64(issuedAt.Unix()),
			ExpiresAt:    uint64(signer.initial.ExpiresAt.Unix()),
			Nonce:        nonces[0],
			Source:       signer.prepared.peerFacts,
			Destination:  signer.prepared.clientFacts,
			TicketHash:   signer.ticketHash,
			ManifestHash: peerManifestSum,
			Files:        peerFiles,
		},
		signer.privateKey,
	)
	if err != nil {
		return SignedPeerResponse{}, ErrInvalidHostTransaction
	}
	if signer.verifyPeerEnvelope(envelope, peerFiles, peerManifestSum, now) != nil {
		clear(envelope)
		return SignedPeerResponse{}, ErrInvalidHostTransaction
	}
	signer.seenNonce[nonces[0]] = struct{}{}
	signer.branch = transactionPeerSigned
	return SignedPeerResponse{PeerToClient: envelope}, nil
}

func (signer *TransactionSigner) SignCancellation(
	now time.Time,
	entropy io.Reader,
) (SignedCancellation, error) {
	if signer == nil ||
		(signer.branch != transactionAwaitingPeer &&
			signer.branch != transactionPeerSigned) ||
		entropy == nil || signer.ensureWithinTicket(now) != nil {
		return SignedCancellation{}, ErrInvalidHostTransaction
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nonces, err := uniqueNonces(entropy, 1, signer.seenNonce)
	if err != nil {
		return SignedCancellation{}, err
	}
	issuedAt := now.UTC().Truncate(time.Second)
	envelope, err := externalpeer.SignCourierMessage(
		externalpeer.CourierMessage{
			Kind:        externalpeer.CourierCancel,
			Sequence:    3,
			RunID:       signer.prepared.runID,
			IssuedAt:    uint64(issuedAt.Unix()),
			ExpiresAt:   uint64(signer.initial.ExpiresAt.Unix()),
			Nonce:       nonces[0],
			Source:      signer.prepared.clientFacts,
			Destination: signer.prepared.peerFacts,
			TicketHash:  signer.ticketHash,
		},
		signer.privateKey,
	)
	if err != nil {
		return SignedCancellation{}, ErrInvalidHostTransaction
	}
	if signer.verifyCancelEnvelope(envelope, now) != nil {
		clear(envelope)
		return SignedCancellation{}, ErrInvalidHostTransaction
	}
	signer.seenNonce[nonces[0]] = struct{}{}
	if signer.branch == transactionPeerSigned {
		signer.branch = transactionPeerSignedCancelled
	} else {
		signer.branch = transactionCancelled
	}
	return SignedCancellation{Cancel: envelope}, nil
}

func (signer *TransactionSigner) ensureWithinTicket(now time.Time) error {
	if signer == nil || signer.initial.ExpiresAt.IsZero() {
		return ErrInvalidHostTransaction
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	if now.Before(signer.initial.IssuedAt) || !now.Before(signer.initial.ExpiresAt) {
		return ErrInvalidHostTransaction
	}
	return nil
}

func (signer *TransactionSigner) verifyInitial(
	input InitialTransactionInput,
	now time.Time,
) error {
	prepared, err := prepareInitialTransaction(input, now)
	if err != nil {
		return err
	}
	defer clear(prepared.clientWGPublic)
	verifier, err := externalpeer.NewCourierVerifier(signer.publicKey)
	if err != nil {
		return err
	}
	if _, err := verifier.Accept(
		signer.initial.RunTicket,
		externalpeer.CourierExpectation{
			Kind: externalpeer.CourierRunTicket, Sequence: 0,
			RunID: prepared.runID, Now: now,
			Source: prepared.clientFacts, Destination: prepared.peerFacts,
			Files: prepared.ticketFiles,
		},
	); err != nil {
		return err
	}
	_, err = verifier.Accept(
		signer.initial.ClientToPeer,
		externalpeer.CourierExpectation{
			Kind: externalpeer.CourierClientToPeer, Sequence: 1,
			RunID: prepared.runID, Now: now,
			Source: prepared.clientFacts, Destination: prepared.peerFacts,
			TicketHash: signer.ticketHash, ManifestHash: prepared.clientManifestSum,
			Files: prepared.clientFiles,
		},
	)
	return err
}

func (signer *TransactionSigner) verifyPeerEnvelope(
	envelope []byte,
	files []externalpeer.CourierFile,
	manifestHash [sha256.Size]byte,
	now time.Time,
) error {
	verifier, err := signer.initialVerifier(now)
	if err != nil {
		return err
	}
	_, err = verifier.Accept(envelope, externalpeer.CourierExpectation{
		Kind: externalpeer.CourierPeerToClient, Sequence: 2,
		RunID: signer.prepared.runID, Now: now,
		Source: signer.prepared.peerFacts, Destination: signer.prepared.clientFacts,
		TicketHash: signer.ticketHash, ManifestHash: manifestHash, Files: files,
	})
	return err
}

func (signer *TransactionSigner) verifyCancelEnvelope(
	envelope []byte,
	now time.Time,
) error {
	verifier, err := signer.initialVerifier(now)
	if err != nil {
		return err
	}
	_, err = verifier.Accept(envelope, externalpeer.CourierExpectation{
		Kind: externalpeer.CourierCancel, Sequence: 3,
		RunID: signer.prepared.runID, Now: now,
		Source: signer.prepared.clientFacts, Destination: signer.prepared.peerFacts,
		TicketHash: signer.ticketHash,
	})
	return err
}

func (signer *TransactionSigner) initialVerifier(
	_ time.Time,
) (*externalpeer.CourierVerifier, error) {
	verifier, err := externalpeer.NewCourierVerifier(signer.publicKey)
	if err != nil {
		return nil, err
	}
	if _, err := verifier.Accept(
		signer.initial.RunTicket,
		externalpeer.CourierExpectation{
			Kind: externalpeer.CourierRunTicket, Sequence: 0,
			RunID: signer.prepared.runID, Now: signer.initial.IssuedAt,
			Source: signer.prepared.clientFacts, Destination: signer.prepared.peerFacts,
			Files: signer.prepared.ticketFiles,
		},
	); err != nil {
		return nil, err
	}
	if _, err := verifier.Accept(
		signer.initial.ClientToPeer,
		externalpeer.CourierExpectation{
			Kind: externalpeer.CourierClientToPeer, Sequence: 1,
			RunID: signer.prepared.runID, Now: signer.initial.IssuedAt,
			Source: signer.prepared.clientFacts, Destination: signer.prepared.peerFacts,
			TicketHash:   signer.ticketHash,
			ManifestHash: signer.prepared.clientManifestSum,
			Files:        signer.prepared.clientFiles,
		},
	); err != nil {
		return nil, err
	}
	return verifier, nil
}

func prepareInitialTransaction(
	input InitialTransactionInput,
	now time.Time,
) (preparedInitial, error) {
	if input.Config.Validate() != nil ||
		input.TicketExpectation.Validate() != nil ||
		len(input.ClientManifest) == 0 {
		return preparedInitial{}, ErrInvalidHostTransaction
	}
	clientFacts, err := input.Config.Client.CourierFacts()
	if err != nil {
		return preparedInitial{}, ErrInvalidHostTransaction
	}
	peerFacts, err := input.Config.Peer.CourierFacts()
	if err != nil {
		return preparedInitial{}, ErrInvalidHostTransaction
	}
	clientDescriptor, err := externalpeer.ParseClientPublicDescriptor(
		input.ClientArtifacts.Descriptor,
		now,
	)
	if err != nil {
		return preparedInitial{}, ErrInvalidHostTransaction
	}
	clientWGPublic, err := base64.StdEncoding.Strict().DecodeString(
		clientDescriptor.WireGuardPublicKey,
	)
	if err != nil || len(clientWGPublic) != 32 {
		clear(clientWGPublic)
		return preparedInitial{}, ErrInvalidHostTransaction
	}
	clientIP := netip.AddrFrom4(clientFacts.IPv4)
	if _, err := externalpeer.DecodeClientPublicDescriptor(
		input.ClientArtifacts.Descriptor,
		input.ClientArtifacts,
		externalpeer.ClientExpectation{
			RunID:              clientDescriptor.RunID,
			Now:                now,
			ClientPlatformUUID: clientFacts.PlatformUUID,
			ClientIPv4:         clientIP,
			ClientMAC:          input.Config.Client.MAC,
			WireGuardPublicKey: clientWGPublic,
		},
	); err != nil {
		clear(clientWGPublic)
		return preparedInitial{}, ErrInvalidHostTransaction
	}
	clientFiles, err := courierFiles(
		externalpeer.ClientArtifactNames[:],
		[][]byte{
			input.ClientArtifacts.Descriptor,
			input.ClientArtifacts.TLSClientCSRDER,
			input.ClientArtifacts.OverlayClientPublicKey,
		},
	)
	if err != nil {
		clear(clientWGPublic)
		return preparedInitial{}, err
	}
	if _, err := externalpeer.DecodeTransferManifest(
		input.ClientManifest,
		clientDescriptor.RunID,
		externalpeer.CourierClientToPeer,
		clientFiles,
	); err != nil {
		clear(clientWGPublic)
		return preparedInitial{}, ErrInvalidHostTransaction
	}
	ticketFiles, err := input.TicketExpectation.FileTable()
	if err != nil {
		clear(clientWGPublic)
		return preparedInitial{}, ErrInvalidHostTransaction
	}
	return preparedInitial{
		runID:             clientDescriptor.RunID,
		clientFacts:       clientFacts,
		peerFacts:         peerFacts,
		ticketFiles:       ticketFiles,
		clientFiles:       clientFiles,
		clientManifestSum: sha256.Sum256(input.ClientManifest),
		clientDescriptor:  clientDescriptor,
		clientWGPublic:    clientWGPublic,
		clientMAC:         input.Config.Client.MAC,
		peerMAC:           input.Config.Peer.MAC,
	}, nil
}

func (signer *TransactionSigner) validatePeerArtifacts(
	artifacts externalpeer.PeerPublicArtifacts,
	now time.Time,
) ([]externalpeer.CourierFile, [sha256.Size]byte, error) {
	clientIP := netip.AddrFrom4(signer.prepared.clientFacts.IPv4)
	peerIP := netip.AddrFrom4(signer.prepared.peerFacts.IPv4)
	if _, err := externalpeer.DecodePeerPublicDescriptor(
		artifacts.Descriptor,
		artifacts,
		externalpeer.PeerExpectation{
			RunID:                    signer.prepared.runID,
			Now:                      now,
			ClientPlatformUUID:       signer.prepared.clientFacts.PlatformUUID,
			PeerPlatformUUID:         signer.prepared.peerFacts.PlatformUUID,
			ClientIPv4:               clientIP,
			PeerIPv4:                 peerIP,
			ClientMAC:                signer.prepared.clientMAC,
			PeerMAC:                  signer.prepared.peerMAC,
			ClientWireGuardPublicKey: signer.prepared.clientWGPublic,
			ClientCSRDER:             signer.clientArtifacts.TLSClientCSRDER,
			OverlayClientPublicKey:   signer.clientArtifacts.OverlayClientPublicKey,
		},
	); err != nil {
		return nil, [sha256.Size]byte{}, ErrInvalidHostTransaction
	}
	payloads := [][]byte{
		artifacts.Descriptor,
		artifacts.CADER,
		artifacts.ServerCertificateDER,
		artifacts.ClientCertificateDER,
		artifacts.OverlayServerPublicKey,
		artifacts.SystemSSHHostPublicKey,
	}
	payloadFiles, err := courierFiles(
		externalpeer.PeerArtifactNames[:len(externalpeer.PeerArtifactNames)-1],
		payloads,
	)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	manifestFile, err := externalpeer.NewCourierFile(
		externalpeer.PeerArtifactNames[len(externalpeer.PeerArtifactNames)-1],
		artifacts.TransferManifest,
	)
	if err != nil {
		return nil, [sha256.Size]byte{}, ErrInvalidHostTransaction
	}
	return append(payloadFiles, manifestFile),
		sha256.Sum256(artifacts.TransferManifest),
		nil
}

func courierFiles(
	names []string,
	payloads [][]byte,
) ([]externalpeer.CourierFile, error) {
	if len(names) != len(payloads) {
		return nil, ErrInvalidHostTransaction
	}
	files := make([]externalpeer.CourierFile, 0, len(names))
	for index, name := range names {
		file, err := externalpeer.NewCourierFile(name, payloads[index])
		if err != nil {
			return nil, ErrInvalidHostTransaction
		}
		files = append(files, file)
	}
	return files, nil
}

func uniqueNonces(
	entropy io.Reader,
	count int,
	existing map[[32]byte]struct{},
) ([][32]byte, error) {
	if entropy == nil || count <= 0 || count > 16 {
		return nil, ErrInvalidHostTransaction
	}
	seen := make(map[[32]byte]struct{}, count+len(existing))
	for nonce := range existing {
		seen[nonce] = struct{}{}
	}
	result := make([][32]byte, 0, count)
	for attempts := 0; len(result) < count && attempts < count*8; attempts++ {
		var nonce [32]byte
		if _, err := io.ReadFull(entropy, nonce[:]); err != nil {
			return nil, ErrInvalidHostTransaction
		}
		if nonce == ([32]byte{}) {
			continue
		}
		if _, exists := seen[nonce]; exists {
			continue
		}
		seen[nonce] = struct{}{}
		result = append(result, nonce)
	}
	if len(result) != count {
		return nil, ErrInvalidHostTransaction
	}
	return result, nil
}

func cloneInitial(value SignedInitialTransaction) SignedInitialTransaction {
	return SignedInitialTransaction{
		RunID:        value.RunID,
		IssuedAt:     value.IssuedAt,
		ExpiresAt:    value.ExpiresAt,
		RunTicket:    append([]byte(nil), value.RunTicket...),
		ClientToPeer: append([]byte(nil), value.ClientToPeer...),
	}
}

func (initial *SignedInitialTransaction) Clear() {
	if initial == nil {
		return
	}
	clear(initial.RunTicket)
	clear(initial.ClientToPeer)
	*initial = SignedInitialTransaction{}
}

func (response *SignedPeerResponse) Clear() {
	if response == nil {
		return
	}
	clear(response.PeerToClient)
	*response = SignedPeerResponse{}
}

func (cancellation *SignedCancellation) Clear() {
	if cancellation == nil {
		return
	}
	clear(cancellation.Cancel)
	*cancellation = SignedCancellation{}
}

func (signer *TransactionSigner) Close() {
	if signer == nil {
		return
	}
	clear(signer.privateKey)
	clear(signer.publicKey)
	clear(signer.prepared.clientWGPublic)
	clear(signer.clientArtifacts.Descriptor)
	clear(signer.clientArtifacts.TLSClientCSRDER)
	clear(signer.clientArtifacts.OverlayClientPublicKey)
	signer.initial.Clear()
	*signer = TransactionSigner{}
}
