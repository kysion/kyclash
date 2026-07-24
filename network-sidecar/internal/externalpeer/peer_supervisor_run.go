package externalpeer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type ValidatedPeerRun struct {
	Run              SupervisorRun
	PeerConfig       PeerConfig
	ClientDescriptor ClientPublicDescriptor
	TicketHash       [32]byte
	CourierVerifier  *CourierVerifier
	ClientFacts      CourierVMFacts
	PeerFacts        CourierVMFacts
	ConsoleUID       uint32
}

func LoadValidatedPeerRun(
	inbox *StableDirectory,
	staging PeerStagingManifest,
	fixedConfig PeerSupervisorConfig,
	ticketExpectation RunTicketExpectation,
	now time.Time,
) (*ValidatedPeerRun, error) {
	if inbox == nil ||
		staging.Validate() != nil ||
		fixedConfig.Validate() != nil ||
		ticketExpectation.Validate() != nil ||
		validateTicketExpectationAgainstStaging(ticketExpectation, staging) != nil {
		return nil, ErrSupervisorState
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := inbox.RequireExactNames(PeerInboxRunNames[:]); err != nil {
		withCancel := append(
			append([]string(nil), PeerInboxRunNames[:]...),
			"cancel-envelope.bin",
			"cancel-wake",
		)
		if cancelErr := inbox.RequireExactNames(withCancel); cancelErr != nil {
			return nil, err
		}
	}
	wake, err := inbox.ReadCreateOnlyFile("wake", 1, 0o600)
	if err != nil || len(wake) != 0 {
		clear(wake)
		return nil, ErrSupervisorState
	}
	clear(wake)
	ticketEnvelope, err := inbox.ReadCreateOnlyFile(
		"run-ticket-envelope.bin",
		MaxChildControlFrame,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	defer clear(ticketEnvelope)
	clientDescriptorBytes, err := inbox.ReadCreateOnlyFile(
		ClientArtifactNames[0],
		MaxDescriptorSize,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	defer clear(clientDescriptorBytes)
	clientCSRDER, err := inbox.ReadCreateOnlyFile(
		ClientArtifactNames[1],
		MaxArtifactSize,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	defer clear(clientCSRDER)
	clientOverlayPublic, err := inbox.ReadCreateOnlyFile(
		ClientArtifactNames[2],
		MaxArtifactSize,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	defer clear(clientOverlayPublic)
	clientManifest, err := inbox.ReadCreateOnlyFile(
		"client-transfer-manifest-v1.json",
		MaxDescriptorSize,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	defer clear(clientManifest)
	clientEnvelope, err := inbox.ReadCreateOnlyFile(
		"client-to-peer-envelope.bin",
		MaxChildControlFrame,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	defer clear(clientEnvelope)

	courierPublic, err := base64.StdEncoding.Strict().DecodeString(
		staging.CourierPublicKeyBase64,
	)
	if err != nil || len(courierPublic) != ed25519.PublicKeySize {
		clear(courierPublic)
		return nil, ErrSupervisorState
	}
	defer clear(courierPublic)
	clientFacts, _ := fixedConfig.Client.CourierFacts()
	peerFacts, _ := fixedConfig.Peer.CourierFacts()
	ticketFiles, err := ticketExpectation.FileTable()
	if err != nil {
		return nil, err
	}
	ticketMessage, err := VerifyCourierMessage(
		ticketEnvelope,
		ed25519.PublicKey(courierPublic),
		now,
	)
	if err != nil {
		return nil, err
	}
	verifier, err := NewCourierVerifier(ed25519.PublicKey(courierPublic))
	if err != nil {
		return nil, err
	}
	if _, err := verifier.Accept(ticketEnvelope, CourierExpectation{
		Kind:        CourierRunTicket,
		Sequence:    0,
		RunID:       ticketMessage.RunID,
		Now:         now,
		Source:      clientFacts,
		Destination: peerFacts,
		Files:       ticketFiles,
	}); err != nil {
		return nil, err
	}
	ticketHash, err := CourierTicketHash(ticketEnvelope)
	if err != nil {
		return nil, err
	}
	clientPayloads := [][]byte{
		clientDescriptorBytes,
		clientCSRDER,
		clientOverlayPublic,
	}
	clientFiles := make([]CourierFile, 0, len(clientPayloads))
	for index, data := range clientPayloads {
		file, err := NewCourierFile(ClientArtifactNames[index], data)
		if err != nil {
			return nil, err
		}
		clientFiles = append(clientFiles, file)
	}
	if _, err := DecodeTransferManifest(
		clientManifest,
		ticketMessage.RunID,
		CourierClientToPeer,
		clientFiles,
	); err != nil {
		return nil, err
	}
	manifestHash := sha256.Sum256(clientManifest)
	if _, err := verifier.Accept(clientEnvelope, CourierExpectation{
		Kind:         CourierClientToPeer,
		Sequence:     1,
		RunID:        ticketMessage.RunID,
		Now:          now,
		Source:       clientFacts,
		Destination:  peerFacts,
		TicketHash:   ticketHash,
		ManifestHash: manifestHash,
		Files:        clientFiles,
	}); err != nil {
		return nil, err
	}
	clientDescriptor, err := ParseClientPublicDescriptor(
		clientDescriptorBytes,
		now,
	)
	if err != nil ||
		clientDescriptor.RunID != ticketMessage.RunID ||
		clientDescriptor.PlatformUUID != fixedConfig.Client.PlatformUUID ||
		clientDescriptor.En0PrivateIPv4 != fixedConfig.Client.IPv4 ||
		!equalMAC(clientDescriptor.En0MAC, fixedConfig.Client.MAC) {
		return nil, ErrInvalidDescriptor
	}
	clientWireGuardPublic, err := base64.StdEncoding.Strict().DecodeString(
		clientDescriptor.WireGuardPublicKey,
	)
	if err != nil || len(clientWireGuardPublic) != 32 {
		clear(clientWireGuardPublic)
		return nil, ErrInvalidDescriptor
	}
	clientExpectation := ClientExpectation{
		RunID:              ticketMessage.RunID,
		Now:                now,
		ClientPlatformUUID: fixedConfig.Client.PlatformUUID,
		ClientIPv4:         clientFactsIPv4(clientFacts),
		ClientMAC:          fixedConfig.Client.MAC,
		WireGuardPublicKey: clientWireGuardPublic,
	}
	clientArtifacts := ClientPublicArtifacts{
		Descriptor:             append([]byte(nil), clientDescriptorBytes...),
		TLSClientCSRDER:        append([]byte(nil), clientCSRDER...),
		OverlayClientPublicKey: append([]byte(nil), clientOverlayPublic...),
	}
	if _, err := DecodeClientPublicDescriptor(
		clientDescriptorBytes,
		clientArtifacts,
		clientExpectation,
	); err != nil {
		clear(clientWireGuardPublic)
		clear(clientArtifacts.Descriptor)
		clear(clientArtifacts.TLSClientCSRDER)
		clear(clientArtifacts.OverlayClientPublicKey)
		return nil, err
	}
	systemHostPublic, err := readSystemSSHHostPublicKey()
	if err != nil {
		clear(clientWireGuardPublic)
		clear(clientArtifacts.Descriptor)
		clear(clientArtifacts.TLSClientCSRDER)
		clear(clientArtifacts.OverlayClientPublicKey)
		return nil, err
	}
	authorizedKeyLine, err := makeAuthorizedKeyLine(clientOverlayPublic)
	if err != nil {
		clear(clientWireGuardPublic)
		clear(clientArtifacts.Descriptor)
		clear(clientArtifacts.TLSClientCSRDER)
		clear(clientArtifacts.OverlayClientPublicKey)
		clear(systemHostPublic)
		return nil, err
	}
	run := SupervisorRun{
		RunID:             ticketMessage.RunID,
		TicketHash:        HashHex(ticketEnvelope),
		ExpiresAt:         time.Unix(clientDescriptor.ExpiresAt, 0),
		AuthorizedKeyLine: authorizedKeyLine,
	}
	peerConfig := PeerConfig{
		RunID:                  run.RunID,
		Now:                    now,
		ExpiresAt:              run.ExpiresAt,
		Client:                 clientExpectation,
		ClientArtifacts:        clientArtifacts,
		PeerPlatformUUID:       fixedConfig.Peer.PlatformUUID,
		PeerIPv4:               clientFactsIPv4(peerFacts),
		PeerMAC:                fixedConfig.Peer.MAC,
		SystemSSHHostPublicKey: systemHostPublic,
	}
	return &ValidatedPeerRun{
		Run:              run,
		PeerConfig:       peerConfig,
		ClientDescriptor: clientDescriptor,
		TicketHash:       ticketHash,
		CourierVerifier:  verifier,
		ClientFacts:      clientFacts,
		PeerFacts:        peerFacts,
		ConsoleUID:       fixedConfig.ConsoleUID,
	}, nil
}

func (run *ValidatedPeerRun) Clear() {
	if run == nil {
		return
	}
	clearPeerConfigPublicArtifacts(&run.PeerConfig)
	if run.CourierVerifier != nil {
		clear(run.CourierVerifier.publicKey)
	}
	*run = ValidatedPeerRun{}
}

func validateTicketExpectationAgainstStaging(
	expectation RunTicketExpectation,
	staging PeerStagingManifest,
) error {
	if expectation.Validate() != nil || staging.Validate() != nil {
		return ErrInvalidStagingManifest
	}
	staged := []StagedFile{
		staging.PeerSupervisor,
		staging.PeerChild,
		staging.PeerConfig,
		staging.ListenerAuditor,
		staging.ForcedCommandHelper,
	}
	for index, file := range staged {
		expected := expectation.Files[index+3]
		if expected.Length == 0 ||
			expected.Length != file.Size ||
			expected.SHA256 != file.SHA256 ||
			validateStagedFile(file) != nil {
			return ErrInvalidStagingManifest
		}
	}
	return nil
}

func makeAuthorizedKeyLine(raw []byte) (string, error) {
	key, err := ssh.ParsePublicKey(raw)
	if err != nil ||
		key.Type() != ssh.KeyAlgoED25519 ||
		!bytes.Equal(key.Marshal(), raw) {
		return "", ErrSSHProof
	}
	line := `from="127.0.0.1",restrict,command="` +
		ForcedCommandHelperPath + `" ` +
		string(ssh.MarshalAuthorizedKey(key))
	if !ValidAuthorizedKeyLine(line) {
		return "", ErrSSHProof
	}
	return line, nil
}

func readSystemSSHHostPublicKey() ([]byte, error) {
	info, err := os.Lstat(SystemSSHHostPublicKeyPath)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return nil, ErrSSHProof
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return nil, ErrSSHProof
	}
	file, err := os.OpenFile(
		SystemSSHHostPublicKeyPath,
		os.O_RDONLY|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, ErrSSHProof
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		clear(data)
		return nil, ErrSSHProof
	}
	key, comment, options, rest, err := ssh.ParseAuthorizedKey(data)
	clear(data)
	if err != nil ||
		key == nil ||
		key.Type() != ssh.KeyAlgoED25519 ||
		len(options) != 0 ||
		len(rest) != 0 ||
		comment != "" && len(comment) > 256 {
		return nil, ErrSSHProof
	}
	return key.Marshal(), nil
}

func clientFactsIPv4(facts CourierVMFacts) netip.Addr {
	return netip.AddrFrom4(facts.IPv4)
}
