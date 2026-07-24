package externalpeer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
)

type SupervisorVMConfig struct {
	Role               string `json:"role"`
	VMName             string `json:"vm_name"`
	PlatformUUID       string `json:"platform_uuid"`
	SSHHostFingerprint string `json:"ssh_host_fingerprint"`
	MAC                string `json:"mac"`
	IPv4               string `json:"ipv4"`
}

type PeerSupervisorConfig struct {
	SchemaVersion uint8              `json:"schema_version"`
	ConsoleUID    uint32             `json:"console_uid"`
	ConsoleGID    uint32             `json:"console_gid"`
	PeerChildUID  uint32             `json:"peer_child_uid"`
	PeerChildGID  uint32             `json:"peer_child_gid"`
	Client        SupervisorVMConfig `json:"client"`
	Peer          SupervisorVMConfig `json:"peer"`
}

func DecodePeerSupervisorConfig(data []byte) (PeerSupervisorConfig, error) {
	if len(data) == 0 || len(data) > MaxDescriptorSize ||
		rejectDuplicateObjectKeys(data) != nil {
		return PeerSupervisorConfig{}, ErrInvalidPeerConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config PeerSupervisorConfig
	if err := decoder.Decode(&config); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		config.Validate() != nil {
		return PeerSupervisorConfig{}, ErrInvalidPeerConfig
	}
	return config, nil
}

func (config PeerSupervisorConfig) Validate() error {
	if config.SchemaVersion != SchemaVersion ||
		config.ConsoleUID == 0 ||
		config.PeerChildUID == 0 ||
		config.ConsoleUID == config.PeerChildUID {
		return ErrInvalidPeerConfig
	}
	client, err := config.Client.CourierFacts()
	if err != nil {
		return err
	}
	peer, err := config.Peer.CourierFacts()
	if err != nil ||
		client.Role != "client" ||
		peer.Role != "peer" ||
		client.PlatformUUID == peer.PlatformUUID ||
		client.MAC == peer.MAC ||
		client.IPv4 == peer.IPv4 {
		return ErrInvalidPeerConfig
	}
	return nil
}

func (config SupervisorVMConfig) CourierFacts() (CourierVMFacts, error) {
	ipv4, err := netip.ParseAddr(config.IPv4)
	if err != nil {
		return CourierVMFacts{}, ErrInvalidPeerConfig
	}
	return NewCourierVMFacts(
		config.Role,
		config.VMName,
		config.PlatformUUID,
		config.SSHHostFingerprint,
		config.MAC,
		ipv4,
	)
}

type RunTicketExpectation struct {
	SchemaVersion uint8            `json:"schema_version"`
	Files         []ArtifactDigest `json:"files"`
}

func DecodeRunTicketExpectation(data []byte) (RunTicketExpectation, error) {
	if len(data) == 0 || len(data) > MaxDescriptorSize ||
		rejectDuplicateObjectKeys(data) != nil {
		return RunTicketExpectation{}, ErrInvalidPeerConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var expectation RunTicketExpectation
	if err := decoder.Decode(&expectation); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		expectation.Validate() != nil {
		return RunTicketExpectation{}, ErrInvalidPeerConfig
	}
	return expectation, nil
}

func (expectation RunTicketExpectation) Validate() error {
	if expectation.SchemaVersion != SchemaVersion ||
		len(expectation.Files) != len(RunTicketArtifactNames) {
		return ErrInvalidPeerConfig
	}
	for index, file := range expectation.Files {
		if file.Name != RunTicketArtifactNames[index] ||
			file.Length == 0 ||
			file.Length > MaxArtifactSize ||
			!validSHA256(file.SHA256) {
			return ErrInvalidPeerConfig
		}
	}
	return nil
}

func (expectation RunTicketExpectation) FileTable() ([]CourierFile, error) {
	if err := expectation.Validate(); err != nil {
		return nil, err
	}
	files := make([]CourierFile, 0, len(expectation.Files))
	for _, value := range expectation.Files {
		decoded, err := hex.DecodeString(value.SHA256)
		if err != nil || len(decoded) != 32 {
			clear(decoded)
			return nil, ErrInvalidPeerConfig
		}
		var digest [32]byte
		copy(digest[:], decoded)
		clear(decoded)
		files = append(files, CourierFile{
			Name:   value.Name,
			Length: value.Length,
			SHA256: digest,
		})
	}
	return files, nil
}
