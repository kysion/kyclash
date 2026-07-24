package externalpeer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type CourierKind uint8

const (
	CourierRunTicket CourierKind = iota
	CourierClientToPeer
	CourierPeerToClient
	CourierCancel
)

var (
	ErrInvalidCourierMessage = errors.New("invalid external-peer courier message")
	ErrCourierSignature      = errors.New("invalid external-peer courier signature")
	ErrCourierReplay         = errors.New("external-peer courier replay")
)

var RunTicketArtifactNames = [...]string{
	"app",
	"client-supervisor",
	"client-harness",
	"peer-supervisor",
	"peer-child",
	"peer-config",
	"listener-auditor",
	"forced-command-helper",
}

type CourierVMFacts struct {
	Role               string
	VMName             string
	PlatformUUID       string
	SSHHostFingerprint string
	MAC                [6]byte
	IPv4               [4]byte
}

type CourierFile struct {
	Name   string
	Length uint64
	SHA256 [sha256.Size]byte
}

type CourierMessage struct {
	Kind         CourierKind
	Sequence     uint64
	RunID        string
	IssuedAt     uint64
	ExpiresAt    uint64
	Nonce        [32]byte
	Source       CourierVMFacts
	Destination  CourierVMFacts
	TicketHash   [32]byte
	ManifestHash [32]byte
	Files        []CourierFile
}

type SignedCourierMessage struct {
	Message   CourierMessage
	Signature [ed25519.SignatureSize]byte
}

type CourierExpectation struct {
	Kind         CourierKind
	Sequence     uint64
	RunID        string
	Now          time.Time
	Source       CourierVMFacts
	Destination  CourierVMFacts
	TicketHash   [32]byte
	ManifestHash [32]byte
	Files        []CourierFile
}

type ArtifactDigest struct {
	Name   string `json:"name"`
	Length uint64 `json:"byte_length"`
	SHA256 string `json:"sha256"`
}

type TransferManifest struct {
	SchemaVersion uint8            `json:"schema_version"`
	RunID         string           `json:"run_id"`
	Direction     string           `json:"direction"`
	Files         []ArtifactDigest `json:"files"`
}

func NewCourierVMFacts(
	role string,
	vmName string,
	platformUUID string,
	sshHostFingerprint string,
	mac string,
	ipv4 netip.Addr,
) (CourierVMFacts, error) {
	parsedMAC, err := net.ParseMAC(mac)
	if err != nil || len(parsedMAC) != 6 || !validUUID(platformUUID) ||
		!validSSHFingerprint(sshHostFingerprint) ||
		!validPrivateAddr(ipv4) ||
		innerPrefix().Contains(ipv4) {
		return CourierVMFacts{}, ErrInvalidCourierMessage
	}
	var result CourierVMFacts
	result.Role = role
	result.VMName = vmName
	result.PlatformUUID = platformUUID
	result.SSHHostFingerprint = sshHostFingerprint
	copy(result.MAC[:], parsedMAC)
	copy(result.IPv4[:], ipv4.AsSlice())
	if err := validateVMFacts(result); err != nil {
		return CourierVMFacts{}, err
	}
	return result, nil
}

func NewCourierFile(name string, data []byte) (CourierFile, error) {
	if !validArtifactName(name) || len(data) > MaxArtifactSize {
		return CourierFile{}, ErrInvalidCourierMessage
	}
	return CourierFile{
		Name:   name,
		Length: uint64(len(data)),
		SHA256: sha256.Sum256(data),
	}, nil
}

func SignCourierMessage(message CourierMessage, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidCourierMessage
	}
	signedBytes, err := message.SignedBytes()
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(privateKey, signedBytes)
	return append(signedBytes, signature...), nil
}

func (message CourierMessage) SignedBytes() ([]byte, error) {
	if err := validateCourierMessage(message, time.Time{}); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.WriteString(CourierDomain)
	buffer.WriteByte(byte(message.Kind))
	writeUint64(&buffer, message.Sequence)
	if err := writeString(&buffer, message.RunID); err != nil {
		return nil, err
	}
	writeUint64(&buffer, message.IssuedAt)
	writeUint64(&buffer, message.ExpiresAt)
	buffer.Write(message.Nonce[:])
	if err := writeVMFacts(&buffer, message.Source); err != nil {
		return nil, err
	}
	if err := writeVMFacts(&buffer, message.Destination); err != nil {
		return nil, err
	}
	buffer.Write(message.TicketHash[:])
	buffer.Write(message.ManifestHash[:])
	if len(message.Files) > int(^uint16(0)) {
		return nil, ErrInvalidCourierMessage
	}
	_ = binary.Write(&buffer, binary.BigEndian, uint16(len(message.Files)))
	for _, file := range message.Files {
		if err := writeString(&buffer, file.Name); err != nil {
			return nil, err
		}
		writeUint64(&buffer, file.Length)
		buffer.Write(file.SHA256[:])
	}
	return buffer.Bytes(), nil
}

func DecodeAndVerifyCourierMessage(
	envelope []byte,
	publicKey ed25519.PublicKey,
	expected CourierExpectation,
) (CourierMessage, error) {
	if len(publicKey) != ed25519.PublicKeySize ||
		len(envelope) <= len(CourierDomain)+ed25519.SignatureSize {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	signedBytes := envelope[:len(envelope)-ed25519.SignatureSize]
	signature := envelope[len(envelope)-ed25519.SignatureSize:]
	if !ed25519.Verify(publicKey, signedBytes, signature) {
		return CourierMessage{}, ErrCourierSignature
	}
	message, err := decodeCourierSignedBytes(signedBytes)
	if err != nil {
		return CourierMessage{}, err
	}
	now := expected.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validateCourierMessage(message, now); err != nil {
		return CourierMessage{}, err
	}
	if message.Kind != expected.Kind ||
		message.Sequence != expected.Sequence ||
		message.RunID != expected.RunID ||
		message.Source != expected.Source ||
		message.Destination != expected.Destination ||
		message.TicketHash != expected.TicketHash ||
		message.ManifestHash != expected.ManifestHash ||
		!equalCourierFiles(message.Files, expected.Files) {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	return message, nil
}

// VerifyCourierMessage authenticates and validates an envelope before a
// caller derives direction-specific expectations from its public fields. It
// does not provide replay state; use CourierVerifier.Accept after binding the
// expected run, roles, VM facts, file table, and ticket hash.
func VerifyCourierMessage(
	envelope []byte,
	publicKey ed25519.PublicKey,
	now time.Time,
) (CourierMessage, error) {
	if len(publicKey) != ed25519.PublicKeySize ||
		len(envelope) <= len(CourierDomain)+ed25519.SignatureSize {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	signedBytes := envelope[:len(envelope)-ed25519.SignatureSize]
	signature := envelope[len(envelope)-ed25519.SignatureSize:]
	if !ed25519.Verify(publicKey, signedBytes, signature) {
		return CourierMessage{}, ErrCourierSignature
	}
	message, err := decodeCourierSignedBytes(signedBytes)
	if err != nil {
		return CourierMessage{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validateCourierMessage(message, now); err != nil {
		return CourierMessage{}, err
	}
	return message, nil
}

func CourierTicketHash(envelope []byte) ([32]byte, error) {
	if len(envelope) <= len(CourierDomain)+ed25519.SignatureSize {
		return [32]byte{}, ErrInvalidCourierMessage
	}
	message, err := decodeCourierSignedBytes(envelope[:len(envelope)-ed25519.SignatureSize])
	if err != nil || message.Kind != CourierRunTicket {
		return [32]byte{}, ErrInvalidCourierMessage
	}
	return sha256.Sum256(envelope), nil
}

func NewNonce() ([32]byte, error) {
	var nonce [32]byte
	_, err := rand.Read(nonce[:])
	return nonce, err
}

// CourierVerifier adds direction, ordering, nonce, and digest replay state to
// the exact stateless signature verifier. A session accepts one ticket, one
// client bundle, then either one peer bundle or one terminal cancellation.
type CourierVerifier struct {
	mu           sync.Mutex
	publicKey    ed25519.PublicKey
	ticketHash   [32]byte
	ticketExpiry uint64
	acceptedKind CourierKind
	ticketSeen   bool
	cancelled    bool
	seenNonce    map[[32]byte]struct{}
	seenDigest   map[[32]byte]struct{}
}

func NewCourierVerifier(publicKey ed25519.PublicKey) (*CourierVerifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidCourierMessage
	}
	return &CourierVerifier{
		publicKey:  append(ed25519.PublicKey(nil), publicKey...),
		seenNonce:  make(map[[32]byte]struct{}),
		seenDigest: make(map[[32]byte]struct{}),
	}, nil
}

func (verifier *CourierVerifier) Accept(
	envelope []byte,
	expected CourierExpectation,
) (CourierMessage, error) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if verifier.cancelled {
		return CourierMessage{}, ErrCourierReplay
	}
	switch expected.Kind {
	case CourierRunTicket:
		if verifier.ticketSeen {
			return CourierMessage{}, ErrCourierReplay
		}
	case CourierClientToPeer:
		if !verifier.ticketSeen || verifier.acceptedKind != CourierRunTicket ||
			expected.TicketHash != verifier.ticketHash {
			return CourierMessage{}, ErrInvalidCourierMessage
		}
	case CourierPeerToClient:
		if !verifier.ticketSeen || verifier.acceptedKind != CourierClientToPeer ||
			expected.TicketHash != verifier.ticketHash {
			return CourierMessage{}, ErrInvalidCourierMessage
		}
	case CourierCancel:
		if !verifier.ticketSeen || verifier.acceptedKind != CourierClientToPeer ||
			expected.TicketHash != verifier.ticketHash {
			return CourierMessage{}, ErrInvalidCourierMessage
		}
	default:
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	message, err := DecodeAndVerifyCourierMessage(envelope, verifier.publicKey, expected)
	if err != nil {
		return CourierMessage{}, err
	}
	if message.Kind == CourierCancel &&
		message.ExpiresAt > verifier.ticketExpiry {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	if _, exists := verifier.seenNonce[message.Nonce]; exists {
		return CourierMessage{}, ErrCourierReplay
	}
	digest := sha256.Sum256(envelope)
	if _, exists := verifier.seenDigest[digest]; exists {
		return CourierMessage{}, ErrCourierReplay
	}
	verifier.seenNonce[message.Nonce] = struct{}{}
	verifier.seenDigest[digest] = struct{}{}
	verifier.acceptedKind = message.Kind
	if message.Kind == CourierRunTicket {
		verifier.ticketSeen = true
		verifier.ticketHash = digest
		verifier.ticketExpiry = message.ExpiresAt
	}
	if message.Kind == CourierCancel {
		verifier.cancelled = true
	}
	return message, nil
}

func EncodeTransferManifest(
	runID string,
	kind CourierKind,
	files []CourierFile,
) ([]byte, error) {
	direction := map[CourierKind]string{
		CourierClientToPeer: "client-to-peer",
		CourierPeerToClient: "peer-to-client",
	}[kind]
	if !validRunID(runID) || direction == "" || !validManifestFileTable(kind, files) {
		return nil, ErrInvalidCourierMessage
	}
	manifest := TransferManifest{
		SchemaVersion: SchemaVersion,
		RunID:         runID,
		Direction:     direction,
		Files:         make([]ArtifactDigest, 0, len(files)),
	}
	for _, file := range files {
		manifest.Files = append(manifest.Files, ArtifactDigest{
			Name:   file.Name,
			Length: file.Length,
			SHA256: hex.EncodeToString(file.SHA256[:]),
		})
	}
	encoded, err := json.Marshal(manifest)
	if err != nil || len(encoded) > MaxDescriptorSize {
		return nil, ErrInvalidCourierMessage
	}
	return append(encoded, '\n'), nil
}

func DecodeTransferManifest(
	data []byte,
	runID string,
	kind CourierKind,
	files []CourierFile,
) (TransferManifest, error) {
	var manifest TransferManifest
	if err := strictDecode(data, &manifest); err != nil {
		return TransferManifest{}, ErrInvalidCourierMessage
	}
	expectedDirection := map[CourierKind]string{
		CourierClientToPeer: "client-to-peer",
		CourierPeerToClient: "peer-to-client",
	}[kind]
	if !validManifestFileTable(kind, files) ||
		manifest.SchemaVersion != SchemaVersion ||
		manifest.RunID != runID ||
		manifest.Direction != expectedDirection ||
		len(manifest.Files) != len(files) {
		return TransferManifest{}, ErrInvalidCourierMessage
	}
	for index, expected := range files {
		actual := manifest.Files[index]
		if actual.Name != expected.Name ||
			actual.Length != expected.Length ||
			actual.SHA256 != hex.EncodeToString(expected.SHA256[:]) {
			return TransferManifest{}, ErrInvalidCourierMessage
		}
	}
	return manifest, nil
}

func validManifestFileTable(kind CourierKind, files []CourierFile) bool {
	var names []string
	switch kind {
	case CourierClientToPeer:
		names = ClientArtifactNames[:]
	case CourierPeerToClient:
		// A transfer manifest describes the six public payload files. The
		// courier file table then adds the exact manifest as the seventh file;
		// this avoids an impossible self-hash.
		names = PeerArtifactNames[:len(PeerArtifactNames)-1]
	default:
		return false
	}
	if len(files) != len(names) {
		return false
	}
	for index, file := range files {
		if file.Name != names[index] ||
			!validArtifactName(file.Name) ||
			file.Length > MaxArtifactSize ||
			isZero32(file.SHA256) {
			return false
		}
	}
	return true
}

func validateCourierMessage(message CourierMessage, now time.Time) error {
	if !validRunID(message.RunID) ||
		message.Sequence != uint64(message.Kind) ||
		isZero32(message.Nonce) ||
		validateVMFacts(message.Source) != nil ||
		validateVMFacts(message.Destination) != nil ||
		message.Source.Role == message.Destination.Role ||
		message.Source.VMName == message.Destination.VMName ||
		message.Source.PlatformUUID == message.Destination.PlatformUUID ||
		message.Source.MAC == message.Destination.MAC ||
		message.Source.IPv4 == message.Destination.IPv4 ||
		!validDirection(message.Kind, message.Source, message.Destination) ||
		!validFileTable(message.Kind, message.Files) {
		return ErrInvalidCourierMessage
	}
	switch message.Kind {
	case CourierRunTicket:
		if !isZero32(message.TicketHash) || !isZero32(message.ManifestHash) {
			return ErrInvalidCourierMessage
		}
	case CourierClientToPeer, CourierPeerToClient:
		if isZero32(message.TicketHash) || isZero32(message.ManifestHash) {
			return ErrInvalidCourierMessage
		}
	case CourierCancel:
		if isZero32(message.TicketHash) || !isZero32(message.ManifestHash) ||
			len(message.Files) != 0 {
			return ErrInvalidCourierMessage
		}
	default:
		return ErrInvalidCourierMessage
	}
	if !now.IsZero() {
		issued := time.Unix(int64(message.IssuedAt), 0)
		expires := time.Unix(int64(message.ExpiresAt), 0)
		if issued.After(now.Add(30*time.Second)) ||
			issued.Before(now.Add(-30*time.Second)) ||
			!expires.After(now) ||
			expires.After(issued.Add(MaxCourierLife)) {
			return ErrInvalidCourierMessage
		}
	}
	return nil
}

func validateVMFacts(facts CourierVMFacts) error {
	if facts.Role != "client" && facts.Role != "peer" ||
		facts.Role == "client" && facts.VMName != ClientVMName ||
		facts.Role == "peer" && facts.VMName != PeerVMName ||
		!validUUID(facts.PlatformUUID) ||
		!validSSHFingerprint(facts.SSHHostFingerprint) ||
		facts.MAC[0]&1 != 0 ||
		isZero6(facts.MAC) {
		return ErrInvalidCourierMessage
	}
	ipv4 := netip.AddrFrom4(facts.IPv4)
	if !validPrivateAddr(ipv4) || innerPrefix().Contains(ipv4) {
		return ErrInvalidCourierMessage
	}
	return nil
}

func validDirection(kind CourierKind, source, destination CourierVMFacts) bool {
	switch kind {
	case CourierRunTicket, CourierClientToPeer, CourierCancel:
		return source.Role == "client" && destination.Role == "peer"
	case CourierPeerToClient:
		return source.Role == "peer" && destination.Role == "client"
	default:
		return false
	}
}

func validFileTable(kind CourierKind, files []CourierFile) bool {
	var names []string
	switch kind {
	case CourierRunTicket:
		names = RunTicketArtifactNames[:]
	case CourierClientToPeer:
		names = ClientArtifactNames[:]
	case CourierPeerToClient:
		names = PeerArtifactNames[:]
	case CourierCancel:
		return len(files) == 0
	default:
		return false
	}
	if len(files) != len(names) {
		return false
	}
	for index, file := range files {
		if file.Name != names[index] ||
			!validArtifactName(file.Name) ||
			file.Length > MaxArtifactSize ||
			isZero32(file.SHA256) {
			return false
		}
	}
	return true
}

func validArtifactName(value string) bool {
	if value == "" || len(value) > 128 ||
		strings.Contains(value, "/") ||
		strings.Contains(value, "\\") ||
		strings.ContainsRune(value, '\x00') ||
		!utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-' ||
			character == '.' {
			continue
		}
		return false
	}
	return true
}

func decodeCourierSignedBytes(data []byte) (CourierMessage, error) {
	if !bytes.HasPrefix(data, []byte(CourierDomain)) {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	reader := bytes.NewReader(data[len(CourierDomain):])
	kind, err := reader.ReadByte()
	if err != nil {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	message := CourierMessage{Kind: CourierKind(kind)}
	if message.Sequence, err = readUint64(reader); err != nil {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	if message.RunID, err = readString(reader); err != nil {
		return CourierMessage{}, err
	}
	if message.IssuedAt, err = readUint64(reader); err != nil {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	if message.ExpiresAt, err = readUint64(reader); err != nil {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	if _, err := io.ReadFull(reader, message.Nonce[:]); err != nil {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	if message.Source, err = readVMFacts(reader); err != nil {
		return CourierMessage{}, err
	}
	if message.Destination, err = readVMFacts(reader); err != nil {
		return CourierMessage{}, err
	}
	if _, err := io.ReadFull(reader, message.TicketHash[:]); err != nil {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	if _, err := io.ReadFull(reader, message.ManifestHash[:]); err != nil {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	var fileCount uint16
	if err := binary.Read(reader, binary.BigEndian, &fileCount); err != nil {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	message.Files = make([]CourierFile, 0, int(fileCount))
	for index := 0; index < int(fileCount); index++ {
		name, err := readString(reader)
		if err != nil {
			return CourierMessage{}, err
		}
		length, err := readUint64(reader)
		if err != nil {
			return CourierMessage{}, ErrInvalidCourierMessage
		}
		file := CourierFile{Name: name, Length: length}
		if _, err := io.ReadFull(reader, file.SHA256[:]); err != nil {
			return CourierMessage{}, ErrInvalidCourierMessage
		}
		message.Files = append(message.Files, file)
	}
	if reader.Len() != 0 {
		return CourierMessage{}, ErrInvalidCourierMessage
	}
	return message, nil
}

func writeVMFacts(buffer *bytes.Buffer, facts CourierVMFacts) error {
	for _, value := range []string{
		facts.Role,
		facts.VMName,
		facts.PlatformUUID,
		facts.SSHHostFingerprint,
	} {
		if err := writeString(buffer, value); err != nil {
			return err
		}
	}
	buffer.Write(facts.MAC[:])
	buffer.Write(facts.IPv4[:])
	return nil
}

func readVMFacts(reader *bytes.Reader) (CourierVMFacts, error) {
	var facts CourierVMFacts
	var err error
	if facts.Role, err = readString(reader); err != nil {
		return CourierVMFacts{}, err
	}
	if facts.VMName, err = readString(reader); err != nil {
		return CourierVMFacts{}, err
	}
	if facts.PlatformUUID, err = readString(reader); err != nil {
		return CourierVMFacts{}, err
	}
	if facts.SSHHostFingerprint, err = readString(reader); err != nil {
		return CourierVMFacts{}, err
	}
	if _, err := io.ReadFull(reader, facts.MAC[:]); err != nil {
		return CourierVMFacts{}, ErrInvalidCourierMessage
	}
	if _, err := io.ReadFull(reader, facts.IPv4[:]); err != nil {
		return CourierVMFacts{}, ErrInvalidCourierMessage
	}
	return facts, nil
}

func writeString(buffer *bytes.Buffer, value string) error {
	if len(value) > int(^uint16(0)) ||
		!utf8.ValidString(value) ||
		strings.ContainsRune(value, '\x00') {
		return ErrInvalidCourierMessage
	}
	_ = binary.Write(buffer, binary.BigEndian, uint16(len(value)))
	buffer.WriteString(value)
	return nil
}

func readString(reader *bytes.Reader) (string, error) {
	var length uint16
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return "", ErrInvalidCourierMessage
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(reader, data); err != nil ||
		!utf8.Valid(data) ||
		bytes.IndexByte(data, 0) >= 0 {
		return "", ErrInvalidCourierMessage
	}
	return string(data), nil
}

func writeUint64(buffer *bytes.Buffer, value uint64) {
	_ = binary.Write(buffer, binary.BigEndian, value)
}

func readUint64(reader *bytes.Reader) (uint64, error) {
	var value uint64
	err := binary.Read(reader, binary.BigEndian, &value)
	return value, err
}

func equalCourierFiles(left, right []CourierFile) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func isZero32(value [32]byte) bool { return value == [32]byte{} }
func isZero6(value [6]byte) bool   { return value == [6]byte{} }
