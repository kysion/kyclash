package externalpeerhost

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/externalpeergueststaging"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
	"golang.org/x/crypto/ssh"
)

var baseGuestReviewNames = []string{
	externalpeergueststaging.ListenerInventoryName,
	externalpeergueststaging.VMIdentityWitnessName,
	externalpeergueststaging.SSHHostPublicKeyName,
	externalpeergueststaging.SSHHostFingerprintName,
	externalpeergueststaging.SSHBootstrapWitnessName,
}

var preparedGuestReviewNames = append(
	append([]string(nil), baseGuestReviewNames...),
	externalpeergueststaging.BaselineCandidateName,
	externalpeergueststaging.ReviewWitnessName,
)

type hostVMIdentityWitness struct {
	SchemaVersion uint8                               `json:"schema_version"`
	Role          externalpeergueststaging.Role       `json:"role"`
	RuntimeTarget string                              `json:"runtime_target"`
	CollectedAt   int64                               `json:"collected_at"`
	Identity      externalpeergueststaging.VMIdentity `json:"identity"`
	AppTreeSHA256 string                              `json:"app_tree_sha256,omitempty"`
}

type hostLayerBReviewWitness struct {
	SchemaVersion     uint8                         `json:"schema_version"`
	Role              externalpeergueststaging.Role `json:"role"`
	ConfigSHA256      string                        `json:"config_sha256"`
	ExpectationSHA256 string                        `json:"expectation_sha256"`
	CourierKeySHA256  string                        `json:"courier_public_key_sha256"`
	InventorySHA256   string                        `json:"listener_inventory_sha256"`
	BaselineSHA256    string                        `json:"listener_baseline_sha256"`
}

type guestReviewSet struct {
	role       string
	root       string
	directory  *secureDirectory
	values     map[string]secureBlob
	identity   hostVMIdentityWitness
	management managementBootstrapWitness
	inventory  externalpeer.ListenerInventory
	baseline   *externalpeer.ListenerBaseline
	review     *hostLayerBReviewWitness
}

func openGuestReviewSet(
	layout Layout,
	role string,
	builds externalPeerBuildInputs,
	managementPublic []byte,
) (*guestReviewSet, error) {
	root := layout.GuestClientOutput
	expectedRole := externalpeergueststaging.ClientRole
	runtimeTarget := vmexternalpeerlab.RuntimeTarget
	vmName := externalpeer.ClientVMName
	if role == "peer" {
		root = layout.GuestPeerOutput
		expectedRole = externalpeergueststaging.PeerRole
		runtimeTarget = vmexternalpeerlab.PeerRuntimeTarget
		vmName = externalpeer.PeerVMName
	} else if role != "client" {
		return nil, ErrUnsafeHostCourier
	}
	directory, err := openSecureDirectory(root, uint32(os.Getuid()))
	if err != nil {
		return nil, err
	}
	result := &guestReviewSet{
		role: role, root: root, directory: directory,
		values: make(map[string]secureBlob, len(preparedGuestReviewNames)),
	}
	fail := func() (*guestReviewSet, error) {
		result.close()
		return nil, ErrUnsafeHostCourier
	}
	prepared := directory.requireExactNames(preparedGuestReviewNames) == nil
	if !prepared && directory.requireExactNames(baseGuestReviewNames) != nil {
		return fail()
	}
	names := baseGuestReviewNames
	if prepared {
		names = preparedGuestReviewNames
	}
	for _, name := range names {
		maximum := externalpeer.MaxDescriptorSize
		if name == externalpeergueststaging.ListenerInventoryName ||
			name == externalpeergueststaging.BaselineCandidateName {
			maximum = externalpeer.MaxChildControlFrame
		}
		blob, err := directory.readStableFile(name, maximum, nil)
		if err != nil {
			return fail()
		}
		result.values[name] = blob
	}
	identityBlob := result.values[externalpeergueststaging.VMIdentityWitnessName]
	if decodeCanonicalHostJSON(identityBlob.bytes, &result.identity) != nil ||
		result.identity.SchemaVersion != 1 ||
		result.identity.Role != expectedRole ||
		result.identity.RuntimeTarget != runtimeTarget ||
		result.identity.CollectedAt <= 0 ||
		result.identity.Identity.Validate() != nil ||
		expectedRole == externalpeergueststaging.ClientRole &&
			result.identity.AppTreeSHA256 != builds.appManifest.TreeSHA256 ||
		expectedRole == externalpeergueststaging.PeerRole &&
			result.identity.AppTreeSHA256 != "" {
		return fail()
	}
	hostBlob := result.values[externalpeergueststaging.SSHHostPublicKeyName]
	hostKey, err := parseCanonicalRawED25519(hostBlob.bytes)
	if err != nil ||
		hashBytes(hostBlob.bytes) !=
			result.identity.Identity.SSHHostPublicKeySHA256 ||
		ssh.FingerprintSHA256(hostKey) !=
			result.identity.Identity.SSHHostKeyFingerprint {
		return fail()
	}
	fingerprintBlob := result.values[externalpeergueststaging.SSHHostFingerprintName]
	if !bytes.Equal(
		fingerprintBlob.bytes,
		[]byte(result.identity.Identity.SSHHostKeyFingerprint+"\n"),
	) {
		return fail()
	}
	managementBlob := result.values[externalpeergueststaging.SSHBootstrapWitnessName]
	if decodeCanonicalHostJSON(managementBlob.bytes, &result.management) != nil {
		return fail()
	}
	expectedVM := externalpeer.SupervisorVMConfig{
		Role: role, VMName: vmName,
		PlatformUUID:       result.identity.Identity.PlatformUUID,
		SSHHostFingerprint: result.identity.Identity.SSHHostKeyFingerprint,
		MAC:                result.identity.Identity.En0MAC,
		IPv4:               result.identity.Identity.En0IPv4,
	}
	knownHosts, err := validateManagementReview(
		role,
		vmName,
		runtimeTarget,
		expectedVM,
		result.management.ConsoleUID,
		result.management.ConsoleGID,
		managementPublic,
		hostBlob.bytes,
		fingerprintBlob.bytes,
		managementBlob.bytes,
	)
	clear(knownHosts)
	if err != nil {
		return fail()
	}
	inventoryBlob := result.values[externalpeergueststaging.ListenerInventoryName]
	result.inventory, err = externalpeer.DecodeListenerInventory(
		inventoryBlob.bytes,
	)
	if err != nil {
		return fail()
	}
	canonicalInventory, err := externalpeer.EncodeListenerInventory(
		result.inventory,
	)
	if err != nil || !bytes.Equal(canonicalInventory, inventoryBlob.bytes) {
		clear(canonicalInventory)
		return fail()
	}
	clear(canonicalInventory)
	if prepared {
		baselineBlob := result.values[externalpeergueststaging.BaselineCandidateName]
		baseline, err := externalpeer.DecodeListenerBaseline(baselineBlob.bytes)
		if err != nil {
			return fail()
		}
		canonicalBaseline, err := externalpeer.EncodeListenerBaseline(baseline)
		if err != nil || !bytes.Equal(canonicalBaseline, baselineBlob.bytes) {
			clear(canonicalBaseline)
			return fail()
		}
		clear(canonicalBaseline)
		result.baseline = &baseline
		reviewBlob := result.values[externalpeergueststaging.ReviewWitnessName]
		var review hostLayerBReviewWitness
		if decodeCanonicalHostJSON(reviewBlob.bytes, &review) != nil ||
			review.SchemaVersion != 1 ||
			review.Role != expectedRole {
			return fail()
		}
		for _, digest := range []string{
			review.ConfigSHA256,
			review.ExpectationSHA256,
			review.CourierKeySHA256,
			review.InventorySHA256,
			review.BaselineSHA256,
		} {
			if !validLowerSHA256(digest) {
				return fail()
			}
		}
		result.review = &review
	}
	if result.revalidate() != nil {
		return fail()
	}
	return result, nil
}

func (review *guestReviewSet) prepared() bool {
	return review != nil && review.baseline != nil && review.review != nil
}

func (review *guestReviewSet) close() {
	if review == nil {
		return
	}
	for name, value := range review.values {
		clear(value.bytes)
		delete(review.values, name)
	}
	_ = review.directory.close()
	*review = guestReviewSet{}
}

func (review *guestReviewSet) revalidate() error {
	if review == nil || review.directory == nil ||
		review.directory.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	for _, value := range review.values {
		if value.witness.revalidate() != nil {
			return ErrUnsafeHostCourier
		}
	}
	return nil
}

func (review *guestReviewSet) blob(name string) (secureBlob, error) {
	if review == nil || review.revalidate() != nil {
		return secureBlob{}, ErrUnsafeHostCourier
	}
	value, exists := review.values[name]
	if !exists {
		return secureBlob{}, ErrUnsafeHostCourier
	}
	return value, nil
}

func decodeCanonicalHostJSON(data []byte, destination any) error {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return ErrUnsafeHostCourier
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return ErrUnsafeHostCourier
	}
	encoded, err := json.Marshal(destination)
	if err != nil {
		return ErrUnsafeHostCourier
	}
	encoded = append(encoded, '\n')
	defer clear(encoded)
	if !bytes.Equal(encoded, data) {
		return ErrUnsafeHostCourier
	}
	return nil
}

func guestIdentityWitnessPath(role string) (string, error) {
	switch role {
	case "client":
		return filepath.Join(
			externalpeergueststaging.ClientReviewRoot,
			externalpeergueststaging.VMIdentityWitnessName,
		), nil
	case "peer":
		return filepath.Join(
			externalpeergueststaging.PeerReviewRoot,
			externalpeergueststaging.VMIdentityWitnessName,
		), nil
	default:
		return "", ErrUnsafeHostCourier
	}
}
