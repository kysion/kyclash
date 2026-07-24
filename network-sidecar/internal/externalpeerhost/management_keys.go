package externalpeerhost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
	"golang.org/x/crypto/ssh"
)

const maximumManagementKeyBytes = 16 * 1024

type managementBootstrapWitness struct {
	SchemaVersion             uint8    `json:"schema_version"`
	Role                      string   `json:"role"`
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

// InitializeManagementKeys creates two independent, role-specific OpenSSH
// Ed25519 identities. The command surface provides no key, path, account, or
// password parameter and every output is create-only beneath the fixed
// repository-private root.
func InitializeManagementKeys(layout Layout, entropy io.Reader) error {
	if entropy == nil {
		return ErrUnsafeHostCourier
	}
	uid := uint32(os.Getuid())
	if err := ensurePrivateRoot(layout.PrivateRoot, uid); err != nil {
		return err
	}
	privateRoot, err := openSecureDirectory(layout.PrivateRoot, uid)
	if err != nil {
		return err
	}
	defer privateRoot.close()
	lock, err := privateRoot.createExactFile(
		managementKeyInitializationLock,
		nil,
	)
	if err != nil {
		return err
	}
	lockPresent := true
	defer func() {
		if lockPresent {
			_ = privateRoot.removeWitness(lock)
		}
	}()
	if !pathAbsent(layout.Management) ||
		!pathAbsent(layout.ManagementPublic) {
		return ErrUnsafeHostCourier
	}
	if err := os.Mkdir(layout.Management, secureDirectoryMode); err != nil {
		return ErrUnsafeHostCourier
	}
	if err := os.Mkdir(layout.ManagementPublic, secureDirectoryMode); err != nil {
		return ErrUnsafeHostCourier
	}
	privateDirectory, err := openSecureDirectory(layout.Management, uid)
	if err != nil {
		return err
	}
	defer privateDirectory.close()
	publicDirectory, err := openSecureDirectory(layout.ManagementPublic, uid)
	if err != nil {
		return err
	}
	defer publicDirectory.close()
	names := []struct {
		private string
		public  string
	}{
		{ClientManagementKeyName, ClientManagementPublicName},
		{PeerManagementKeyName, PeerManagementPublicName},
	}
	type keyMaterial struct {
		private []byte
		public  []byte
	}
	materials := make([]keyMaterial, 0, len(names))
	defer func() {
		for index := range materials {
			clear(materials[index].private)
			clear(materials[index].public)
		}
	}()
	for range names {
		public, private, err := ed25519.GenerateKey(entropy)
		if err != nil {
			return ErrUnsafeHostCourier
		}
		block, err := ssh.MarshalPrivateKey(private, "")
		if err != nil {
			clear(private)
			clear(public)
			return ErrUnsafeHostCourier
		}
		privateBytes := pem.EncodeToMemory(block)
		clear(block.Bytes)
		clear(private)
		clear(public)
		if len(privateBytes) == 0 ||
			len(privateBytes) > maximumManagementKeyBytes {
			clear(privateBytes)
			return ErrUnsafeHostCourier
		}
		rawPublic, err := rawManagementPublicFromPrivate(privateBytes)
		if err != nil {
			clear(privateBytes)
			return err
		}
		if len(materials) != 0 &&
			bytes.Equal(materials[0].public, rawPublic) {
			clear(privateBytes)
			clear(rawPublic)
			return ErrUnsafeHostCourier
		}
		materials = append(materials, keyMaterial{
			private: privateBytes,
			public:  rawPublic,
		})
	}
	for index, names := range names {
		privateWitness, err := privateDirectory.createExactFile(
			names.private,
			materials[index].private,
		)
		if err != nil {
			return err
		}
		if _, err := publicDirectory.createExactFile(
			names.public,
			materials[index].public,
		); err != nil {
			return err
		}
		if privateWitness.revalidate() != nil {
			return ErrUnsafeHostCourier
		}
	}
	if privateDirectory.requireExactNames(managementPrivateNames) != nil ||
		publicDirectory.requireExactNames(managementPublicNames) != nil ||
		privateRoot.removeWitness(lock) != nil {
		return ErrUnsafeHostCourier
	}
	lockPresent = false
	return nil
}

// PinReviewedManagementHostKeys imports only the six fixed, public review
// files emitted by the two visible guest bootstrap transactions. It never
// scans a network and never accepts a first-seen SSH key.
func PinReviewedManagementHostKeys(layout Layout) error {
	uid := uint32(os.Getuid())
	privateDirectory, err := openSecureDirectory(layout.Management, uid)
	if err != nil {
		return err
	}
	defer privateDirectory.close()
	if privateDirectory.requireExactNames(managementPrivateNames) != nil {
		return ErrUnsafeHostCourier
	}
	publicDirectory, err := openSecureDirectory(
		layout.ManagementPublic,
		uid,
	)
	if err != nil {
		return err
	}
	defer publicDirectory.close()
	if publicDirectory.requireExactNames(managementPublicNames) != nil {
		return ErrUnsafeHostCourier
	}
	reviewDirectory, err := openSecureDirectory(
		layout.ManagementReview,
		uid,
	)
	if err != nil {
		return err
	}
	defer reviewDirectory.close()
	if reviewDirectory.requireExactNames(managementReviewNames) != nil {
		return ErrUnsafeHostCourier
	}
	config, configBlobs, controlDirectory, err := loadManagementPinConfig(
		layout,
		uid,
	)
	if err != nil {
		return err
	}
	defer controlDirectory.close()
	defer clearBlobs(configBlobs)
	type pendingKnownHosts struct {
		name string
		data []byte
	}
	pending := make([]pendingKnownHosts, 0, 2)
	defer func() {
		for index := range pending {
			clear(pending[index].data)
		}
	}()
	for _, role := range []struct {
		role            string
		vmName          string
		runtimeTarget   string
		expectedFacts   externalpeer.SupervisorVMConfig
		privateName     string
		managementPub   string
		hostPublic      string
		hostFingerprint string
		witness         string
		knownHosts      string
	}{
		{
			"client", externalpeer.ClientVMName,
			vmexternalpeerlab.RuntimeTarget, config.Client,
			ClientManagementKeyName, ClientManagementPublicName,
			ClientHostPublicReviewName, ClientHostFingerprintName,
			ClientSSHBootstrapWitnessName, ClientKnownHostsName,
		},
		{
			"peer", externalpeer.PeerVMName,
			vmexternalpeerlab.PeerRuntimeTarget, config.Peer,
			PeerManagementKeyName, PeerManagementPublicName,
			PeerHostPublicReviewName, PeerHostFingerprintName,
			PeerSSHBootstrapWitnessName, PeerKnownHostsName,
		},
	} {
		privateBlob, err := privateDirectory.readStableFile(
			role.privateName,
			maximumManagementKeyBytes,
			nil,
		)
		if err != nil {
			return err
		}
		publicBlob, err := publicDirectory.readStableFile(
			role.managementPub,
			4096,
			nil,
		)
		if err != nil {
			clear(privateBlob.bytes)
			return err
		}
		expectedPublic, err := rawManagementPublicFromPrivate(
			privateBlob.bytes,
		)
		clear(privateBlob.bytes)
		if err != nil ||
			!bytes.Equal(expectedPublic, publicBlob.bytes) {
			clear(expectedPublic)
			clear(publicBlob.bytes)
			return ErrUnsafeHostCourier
		}
		clear(expectedPublic)
		hostBlob, err := reviewDirectory.readStableFile(
			role.hostPublic,
			4096,
			nil,
		)
		if err != nil {
			clear(publicBlob.bytes)
			return err
		}
		fingerprintBlob, err := reviewDirectory.readStableFile(
			role.hostFingerprint,
			256,
			nil,
		)
		if err != nil {
			clear(publicBlob.bytes)
			clear(hostBlob.bytes)
			return err
		}
		witnessBlob, err := reviewDirectory.readStableFile(
			role.witness,
			externalpeer.MaxDescriptorSize,
			nil,
		)
		if err != nil {
			clear(publicBlob.bytes)
			clear(hostBlob.bytes)
			clear(fingerprintBlob.bytes)
			return err
		}
		knownHosts, err := validateManagementReview(
			role.role,
			role.vmName,
			role.runtimeTarget,
			role.expectedFacts,
			config.ConsoleUID,
			config.ConsoleGID,
			publicBlob.bytes,
			hostBlob.bytes,
			fingerprintBlob.bytes,
			witnessBlob.bytes,
		)
		clear(publicBlob.bytes)
		clear(hostBlob.bytes)
		clear(fingerprintBlob.bytes)
		clear(witnessBlob.bytes)
		if err != nil {
			clear(knownHosts)
			return err
		}
		pending = append(pending, pendingKnownHosts{
			name: role.knownHosts,
			data: knownHosts,
		})
	}
	created := make([]fileWitness, 0, len(pending))
	for _, value := range pending {
		witness, err := privateDirectory.createExactFile(
			value.name,
			value.data,
		)
		if err != nil {
			for index := len(created) - 1; index >= 0; index-- {
				if privateDirectory.removeWitness(created[index]) != nil {
					return ErrUnsafeHostCourier
				}
			}
			return err
		}
		created = append(created, witness)
	}
	if privateDirectory.requireExactNames(managementNames) != nil ||
		publicDirectory.requireExactNames(managementPublicNames) != nil ||
		reviewDirectory.requireExactNames(managementReviewNames) != nil ||
		controlDirectory.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	return nil
}

func loadManagementPinConfig(
	layout Layout,
	uid uint32,
) (
	externalpeer.PeerSupervisorConfig,
	[]secureBlob,
	*secureDirectory,
	error,
) {
	directory, err := openSecureDirectory(layout.Control, uid)
	if err != nil {
		return externalpeer.PeerSupervisorConfig{}, nil, nil, err
	}
	if directory.requireExactNames(controlInputNames) != nil {
		directory.close()
		return externalpeer.PeerSupervisorConfig{}, nil, nil, ErrUnsafeHostCourier
	}
	configBlob, err := directory.readStableFile(
		PeerConfigName,
		externalpeer.MaxDescriptorSize,
		nil,
	)
	if err != nil {
		directory.close()
		return externalpeer.PeerSupervisorConfig{}, nil, nil, err
	}
	expectationBlob, err := directory.readStableFile(
		TicketExpectationName,
		externalpeer.MaxDescriptorSize,
		nil,
	)
	if err != nil {
		clear(configBlob.bytes)
		directory.close()
		return externalpeer.PeerSupervisorConfig{}, nil, nil, err
	}
	config, err := externalpeer.DecodePeerSupervisorConfig(configBlob.bytes)
	if err != nil || config.Validate() != nil {
		clear(configBlob.bytes)
		clear(expectationBlob.bytes)
		directory.close()
		return externalpeer.PeerSupervisorConfig{}, nil, nil, ErrUnsafeHostCourier
	}
	if _, err := externalpeer.DecodeRunTicketExpectation(
		expectationBlob.bytes,
	); err != nil {
		clear(configBlob.bytes)
		clear(expectationBlob.bytes)
		directory.close()
		return externalpeer.PeerSupervisorConfig{}, nil, nil, ErrUnsafeHostCourier
	}
	return config, []secureBlob{configBlob, expectationBlob}, directory, nil
}

func validateManagementReview(
	role string,
	vmName string,
	runtimeTarget string,
	expectedFacts externalpeer.SupervisorVMConfig,
	consoleUID uint32,
	consoleGID uint32,
	managementPublic []byte,
	hostPublic []byte,
	fingerprintFile []byte,
	witnessData []byte,
) ([]byte, error) {
	managementKey, err := parseCanonicalRawED25519(managementPublic)
	if err != nil {
		return nil, err
	}
	hostKey, err := parseCanonicalRawED25519(hostPublic)
	if err != nil {
		return nil, err
	}
	hostFingerprint := ssh.FingerprintSHA256(hostKey)
	if !bytes.Equal(
		fingerprintFile,
		[]byte(hostFingerprint+"\n"),
	) ||
		hostFingerprint != expectedFacts.SSHHostFingerprint {
		return nil, ErrUnsafeHostCourier
	}
	var witness managementBootstrapWitness
	decoder := json.NewDecoder(bytes.NewReader(witnessData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&witness); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrUnsafeHostCourier
	}
	canonical, err := json.Marshal(witness)
	if err != nil {
		return nil, ErrUnsafeHostCourier
	}
	canonical = append(canonical, '\n')
	allowedUsers := []string{managementConsoleUser}
	restricted := false
	regenerated := false
	if role == "peer" {
		allowedUsers = append(allowedUsers, "kyclashlabssh")
		restricted = true
		regenerated = true
	}
	if !bytes.Equal(canonical, witnessData) ||
		witness.SchemaVersion != 1 ||
		witness.Role != role ||
		witness.RuntimeTarget != runtimeTarget ||
		witness.ConsoleUser != managementConsoleUser ||
		witness.ConsoleUID != consoleUID ||
		witness.ConsoleGID != consoleGID ||
		!witness.RemoteLoginVerified ||
		!witness.PublicKeyOnlyVerified ||
		!witness.ForwardingDisabled ||
		!witness.RootLoginDisabled ||
		!equalStrings(witness.AllowedUsers, allowedUsers) ||
		witness.ManagementKeySHA256 != hashHex(managementPublic) ||
		witness.ManagementKeyFingerprint !=
			ssh.FingerprintSHA256(managementKey) ||
		!validLowerSHA256(witness.AuthorizedKeysSHA256) ||
		witness.HostKeySHA256 != hashHex(hostPublic) ||
		witness.HostKeyFingerprint != hostFingerprint ||
		witness.RestrictedAccountVerified != restricted ||
		witness.PeerHostKeysRegenerated != regenerated ||
		!validLowerSHA256(witness.RecoveryRecordSHA256) ||
		witness.CompletedAt <= 0 {
		return nil, ErrUnsafeHostCourier
	}
	authorized := ssh.MarshalAuthorizedKey(hostKey)
	if len(authorized) == 0 ||
		!bytes.HasSuffix(authorized, []byte("\n")) {
		return nil, ErrUnsafeHostCourier
	}
	return append([]byte(vmName+" "), authorized...), nil
}

func rawManagementPublicFromPrivate(data []byte) ([]byte, error) {
	private, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, ErrUnsafeHostCourier
	}
	var key ed25519.PrivateKey
	switch value := private.(type) {
	case *ed25519.PrivateKey:
		if value != nil {
			key = *value
		}
	case ed25519.PrivateKey:
		key = value
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrUnsafeHostCourier
	}
	defer clear(key)
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrUnsafeHostCourier
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil || sshPublic.Type() != ssh.KeyAlgoED25519 {
		return nil, ErrUnsafeHostCourier
	}
	return append([]byte(nil), sshPublic.Marshal()...), nil
}

func parseCanonicalRawED25519(data []byte) (ssh.PublicKey, error) {
	key, err := ssh.ParsePublicKey(data)
	if err != nil ||
		key == nil ||
		key.Type() != ssh.KeyAlgoED25519 ||
		!bytes.Equal(key.Marshal(), data) {
		return nil, ErrUnsafeHostCourier
	}
	return key, nil
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmtHex(sum[:])
}

func validLowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
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
