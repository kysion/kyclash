package externalpeergueststaging

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
	"golang.org/x/crypto/ssh"
)

const (
	restrictedSSHAccount = "kyclashlabssh"
	restrictedSSHUID     = 502
	restrictedSSHGID     = 20
	maximumSSHPublicKey  = 4 * 1024
)

type SSHBootstrapRequest struct {
	Role                     Role
	RuntimeTarget            string
	ConsoleUID               uint32
	ConsoleGID               uint32
	ManagementPublicKey      []byte
	ManagementKeySHA256      string
	ManagementKeyFingerprint string
}

type SSHBootstrapEvidence struct {
	SchemaVersion             uint8    `json:"schema_version"`
	Role                      Role     `json:"role"`
	RuntimeTarget             string   `json:"runtime_target"`
	ConsoleUser               string   `json:"console_user"`
	ConsoleUID                uint32   `json:"console_uid"`
	ConsoleGID                uint32   `json:"console_gid"`
	RemoteLoginVerified       bool     `json:"remote_login_verified"`
	PublicKeyOnlyVerified     bool     `json:"public_key_only_verified"`
	ForwardingDisabled        bool     `json:"forwarding_disabled"`
	RootLoginDisabled         bool     `json:"root_login_disabled"`
	AllowedUsers              []string `json:"allowed_users"`
	ManagementKeySHA256       string   `json:"management_public_key_sha256"`
	ManagementKeyFingerprint  string   `json:"management_public_key_fingerprint"`
	AuthorizedKeysSHA256      string   `json:"authorized_keys_sha256"`
	HostKeySHA256             string   `json:"host_public_key_sha256"`
	HostKeyFingerprint        string   `json:"host_public_key_fingerprint"`
	RestrictedAccountVerified bool     `json:"restricted_account_verified"`
	PeerHostKeysRegenerated   bool     `json:"peer_host_keys_regenerated"`
	RecoveryRecordSHA256      string   `json:"recovery_record_sha256"`
	CompletedAt               int64    `json:"completed_at"`
}

type SSHBootstrapResult struct {
	Evidence      SSHBootstrapEvidence
	HostPublicKey []byte
}

type SSHBootstrapper interface {
	Bootstrap(context.Context, SSHBootstrapRequest) (SSHBootstrapResult, error)
}

func (value *runner) runLayerASSHBootstrap(
	input *stableDirectory,
) (Result, error) {
	reviewRoot := value.layout.review(value.role)
	if err := requireReviewNames(
		reviewRoot,
		value.rootUID,
		value.rootGID,
		[]string{ListenerInventoryName, VMIdentityWitnessName},
	); err != nil {
		return Result{}, err
	}
	layerAIdentity, err := value.readLayerAIdentityWitness()
	if err != nil ||
		!value.currentIdentity.equalFull(layerAIdentity.Identity) {
		return Result{}, ErrGuestStaging
	}
	keyName := ClientManagementPublicKeyName
	if value.role == PeerRole {
		keyName = PeerManagementPublicKeyName
	}
	keyBlob, err := input.readStableFile(
		keyName,
		inputFileMode,
		maximumSSHPublicKey,
		value.hooks.afterRead,
	)
	if err != nil {
		return Result{}, err
	}
	defer keyBlob.clear()
	key, err := parseCanonicalRawED25519(keyBlob.bytes)
	if err != nil {
		return Result{}, err
	}
	request := SSHBootstrapRequest{
		Role:                     value.role,
		RuntimeTarget:            value.facts.RuntimeTarget,
		ConsoleUID:               value.facts.ConsoleUID,
		ConsoleGID:               value.facts.ConsoleGID,
		ManagementPublicKey:      append([]byte(nil), keyBlob.bytes...),
		ManagementKeySHA256:      keyBlob.identity.SHA256,
		ManagementKeyFingerprint: ssh.FingerprintSHA256(key),
	}
	defer clear(request.ManagementPublicKey)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	bootstrapped, err := value.bootstrap.Bootstrap(ctx, request)
	if err != nil || keyBlob.revalidate() != nil ||
		validateSSHBootstrapResult(request, bootstrapped) != nil {
		clear(bootstrapped.HostPublicKey)
		return Result{}, ErrGuestStaging
	}
	defer clear(bootstrapped.HostPublicKey)
	finalIdentity, err := value.identity(ctx)
	if err != nil ||
		!finalIdentity.equalImmutable(value.currentIdentity) ||
		finalIdentity.En0IPv4 != value.currentIdentity.En0IPv4 ||
		finalIdentity.SSHHostPublicKeySHA256 !=
			hashHex(bootstrapped.HostPublicKey) ||
		finalIdentity.SSHHostKeyFingerprint !=
			bootstrapped.Evidence.HostKeyFingerprint ||
		value.role == ClientRole &&
			!finalIdentity.equalFull(value.currentIdentity) {
		return Result{}, ErrGuestStaging
	}
	witnessBytes, err := encodeSSHBootstrapEvidence(bootstrapped.Evidence)
	if err != nil {
		return Result{}, err
	}
	defer clear(witnessBytes)
	fingerprintBytes := []byte(bootstrapped.Evidence.HostKeyFingerprint + "\n")
	defer clear(fingerprintBytes)

	outputs := []struct {
		name string
		data []byte
	}{
		{SSHHostPublicKeyName, bootstrapped.HostPublicKey},
		{SSHHostFingerprintName, fingerprintBytes},
		{SSHBootstrapWitnessName, witnessBytes},
	}
	for _, output := range outputs {
		path := filepath.Join(reviewRoot, output.name)
		_, createErr := value.transaction.stageFile(
			path,
			output.data,
			reviewFileMode,
			reviewDirectoryMode,
		)
		if createErr != nil {
			return Result{}, createErr
		}
	}
	result := Result{
		Role:       value.role,
		Phase:      value.phase,
		ReviewPath: filepath.Join(reviewRoot, SSHBootstrapWitnessName),
		ReviewSHA:  hashHex(witnessBytes),
	}
	return value.transaction.commit(result, finalIdentity)
}

func parseCanonicalRawED25519(data []byte) (ssh.PublicKey, error) {
	key, err := ssh.ParsePublicKey(data)
	if err != nil ||
		key == nil ||
		key.Type() != ssh.KeyAlgoED25519 ||
		!bytes.Equal(key.Marshal(), data) {
		return nil, ErrGuestStaging
	}
	return key, nil
}

func validateSSHBootstrapResult(
	request SSHBootstrapRequest,
	result SSHBootstrapResult,
) error {
	hostKey, err := parseCanonicalRawED25519(result.HostPublicKey)
	if err != nil {
		return err
	}
	evidence := result.Evidence
	expectedTarget := vmexternalpeerlab.RuntimeTarget
	expectedUsers := []string{evidence.ConsoleUser}
	restricted := false
	regenerated := false
	if request.Role == PeerRole {
		expectedTarget = vmexternalpeerlab.PeerRuntimeTarget
		expectedUsers = append(expectedUsers, restrictedSSHAccount)
		restricted = true
		regenerated = true
	}
	if evidence.SchemaVersion != 1 ||
		evidence.Role != request.Role ||
		evidence.RuntimeTarget != expectedTarget ||
		request.RuntimeTarget != expectedTarget ||
		!validAccountName(evidence.ConsoleUser) ||
		evidence.ConsoleUID != request.ConsoleUID ||
		evidence.ConsoleGID != request.ConsoleGID ||
		!evidence.RemoteLoginVerified ||
		!evidence.PublicKeyOnlyVerified ||
		!evidence.ForwardingDisabled ||
		!evidence.RootLoginDisabled ||
		!equalStrings(evidence.AllowedUsers, expectedUsers) ||
		evidence.ManagementKeySHA256 != request.ManagementKeySHA256 ||
		evidence.ManagementKeyFingerprint != request.ManagementKeyFingerprint ||
		!validSHA256(evidence.AuthorizedKeysSHA256) ||
		evidence.HostKeySHA256 != hashHex(result.HostPublicKey) ||
		evidence.HostKeyFingerprint != ssh.FingerprintSHA256(hostKey) ||
		evidence.RestrictedAccountVerified != restricted ||
		evidence.PeerHostKeysRegenerated != regenerated ||
		!validSHA256(evidence.RecoveryRecordSHA256) ||
		evidence.CompletedAt <= 0 {
		return ErrGuestStaging
	}
	return nil
}

func encodeSSHBootstrapEvidence(
	evidence SSHBootstrapEvidence,
) ([]byte, error) {
	if evidence.SchemaVersion != 1 ||
		evidence.ValidatePublicShape() != nil {
		return nil, ErrGuestStaging
	}
	encoded, err := json.Marshal(evidence)
	if err != nil || len(encoded) > externalpeer.MaxDescriptorSize {
		return nil, ErrGuestStaging
	}
	return append(encoded, '\n'), nil
}

func (evidence SSHBootstrapEvidence) ValidatePublicShape() error {
	if evidence.Role != ClientRole && evidence.Role != PeerRole ||
		!validAccountName(evidence.ConsoleUser) ||
		evidence.ConsoleUID == 0 ||
		len(evidence.AllowedUsers) == 0 ||
		!validSHA256(evidence.ManagementKeySHA256) ||
		!strings.HasPrefix(evidence.ManagementKeyFingerprint, "SHA256:") ||
		!validSHA256(evidence.AuthorizedKeysSHA256) ||
		!validSHA256(evidence.HostKeySHA256) ||
		!strings.HasPrefix(evidence.HostKeyFingerprint, "SHA256:") ||
		!validSHA256(evidence.RecoveryRecordSHA256) ||
		evidence.CompletedAt <= 0 {
		return ErrGuestStaging
	}
	for _, name := range evidence.AllowedUsers {
		if !validAccountName(name) {
			return ErrGuestStaging
		}
	}
	return nil
}

func validAccountName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(index > 0 && character >= '0' && character <= '9') ||
			(index > 0 && (character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func equalStrings(left []string, right []string) bool {
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

func sshBootstrapReviewNames() []string {
	return []string{
		ListenerInventoryName,
		VMIdentityWitnessName,
		SSHHostPublicKeyName,
		SSHHostFingerprintName,
		SSHBootstrapWitnessName,
	}
}
