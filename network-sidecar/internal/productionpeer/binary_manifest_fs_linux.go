//go:build linux

package productionpeer

import (
	"crypto/sha256"
	"errors"
	"hash"

	"golang.org/x/sys/unix"
)

const (
	binaryIdentityManifestPathV1      = "/usr/lib/kyclash/network-peer-binaries-v1.json"
	binaryIdentityManifestFileNameV1  = "network-peer-binaries-v1.json"
	binaryIdentityManifestDirectoryV1 = "/usr/lib/kyclash"

	binaryIdentityPeerPathV1          = "/usr/libexec/kyclash-network-peer"
	binaryIdentityPeerFileNameV1      = "kyclash-network-peer"
	binaryIdentityBrokerPathV1        = "/usr/libexec/kyclash-network-peer-broker"
	binaryIdentityBrokerFileNameV1    = "kyclash-network-peer-broker"
	binaryIdentityBootstrapPathV1     = "/usr/libexec/kyclash-network-peer-host-bootstrap"
	binaryIdentityBootstrapFileNameV1 = "kyclash-network-peer-host-bootstrap"
	binaryIdentityExecutableDirectory = "/usr/libexec"

	binaryIdentityMaxExecutableSizeV1 = 256 * 1024 * 1024
	binaryIdentityMaxXattrSizeV1      = 4 * 1024
	binaryIdentityReadBufferSizeV1    = 64 * 1024

	binaryIdentityACLAccessXattrV1  = "system.posix_acl_access"
	binaryIdentityACLDefaultXattrV1 = "system.posix_acl_default"
	binaryIdentityCapabilityXattrV1 = "security.capability"

	binaryIdentityManifestModeV1   = unix.S_IFREG | 0o644
	binaryIdentityExecutableModeV1 = unix.S_IFREG | 0o755
)

var binaryIdentityExecutableNamesV1 = [...]string{
	binaryIdentityPeerFileNameV1,
	binaryIdentityBrokerFileNameV1,
	binaryIdentityBootstrapFileNameV1,
}

type binaryIdentityFilesystemOpsV1 interface {
	open(path string, flags int, mode uint32) (int, error)
	openat2(directoryDescriptor int, path string, how *unix.OpenHow) (int, error)
	close(descriptor int) error
	statx(directoryDescriptor int, path string, flags int, mask int, facts *unix.Statx_t) error
	readXattr(descriptor int, name string) (binaryIdentityXattrV1, error)
	pread(descriptor int, destination []byte, offset int64) (int, error)
}

type linuxBinaryIdentityFilesystemOpsV1 struct{}

func (linuxBinaryIdentityFilesystemOpsV1) open(
	path string,
	flags int,
	mode uint32,
) (int, error) {
	return unix.Open(path, flags, mode)
}

func (linuxBinaryIdentityFilesystemOpsV1) openat2(
	directoryDescriptor int,
	path string,
	how *unix.OpenHow,
) (int, error) {
	return unix.Openat2(directoryDescriptor, path, how)
}

func (linuxBinaryIdentityFilesystemOpsV1) close(descriptor int) error {
	return unix.Close(descriptor)
}

func (linuxBinaryIdentityFilesystemOpsV1) statx(
	directoryDescriptor int,
	path string,
	flags int,
	mask int,
	facts *unix.Statx_t,
) error {
	return unix.Statx(directoryDescriptor, path, flags, mask, facts)
}

func (linuxBinaryIdentityFilesystemOpsV1) readXattr(
	descriptor int,
	name string,
) (result binaryIdentityXattrV1, resultErr error) {
	var encoded [binaryIdentityMaxXattrSizeV1]byte
	defer clear(encoded[:])

	length, err := unix.Fgetxattr(descriptor, name, encoded[:])
	switch {
	case errors.Is(err, unix.ENODATA):
		return binaryIdentityXattrV1{}, nil
	case err != nil, length < 0, length > len(encoded):
		return binaryIdentityXattrV1{}, errBinaryIdentityManifestUnavailableV1
	}
	result.present = true
	result.encoded = make([]byte, length)
	copy(result.encoded, encoded[:length])
	return result, nil
}

func (linuxBinaryIdentityFilesystemOpsV1) pread(
	descriptor int,
	destination []byte,
	offset int64,
) (int, error) {
	return unix.Pread(descriptor, destination, offset)
}

type binaryIdentityXattrV1 struct {
	present bool
	encoded []byte
}

func (attribute *binaryIdentityXattrV1) clear() {
	if attribute == nil {
		return
	}
	if cap(attribute.encoded) > 0 {
		clear(attribute.encoded[:cap(attribute.encoded)])
	}
	attribute.encoded = nil
	attribute.present = false
}

type binaryIdentityObjectFactsV1 struct {
	mask           uint32
	attributes     uint64
	attributesMask uint64
	nlink          uint32
	uid            uint32
	gid            uint32
	mode           uint16
	inode          uint64
	size           uint64
	blocks         uint64
	ctimeSeconds   int64
	ctimeNanos     uint32
	mtimeSeconds   int64
	mtimeNanos     uint32
	deviceMajor    uint32
	deviceMinor    uint32
	mountID        uint64
}

type binaryIdentityObservationV1 struct {
	object       binaryIdentityObjectFactsV1
	accessACL    binaryIdentityXattrV1
	defaultACL   binaryIdentityXattrV1
	capabilities binaryIdentityXattrV1
}

func (observation *binaryIdentityObservationV1) clear() {
	if observation == nil {
		return
	}
	observation.accessACL.clear()
	observation.defaultACL.clear()
	observation.capabilities.clear()
}

type binaryIdentityDirectoryLeaseV1 struct {
	pathDescriptor int
	dataDescriptor int
	parent         *binaryIdentityDirectoryLeaseV1
	name           string
	initial        binaryIdentityObservationV1
	pathFacts      binaryIdentityObjectFactsV1
	root           bool
}

func (lease *binaryIdentityDirectoryLeaseV1) close(
	operations binaryIdentityFilesystemOpsV1,
) {
	if lease == nil || operations == nil {
		return
	}
	lease.initial.clear()
	if lease.dataDescriptor >= 0 {
		_ = operations.close(lease.dataDescriptor)
		lease.dataDescriptor = -1
	}
	if lease.pathDescriptor >= 0 {
		_ = operations.close(lease.pathDescriptor)
		lease.pathDescriptor = -1
	}
}

type binaryIdentityFileLeaseV1 struct {
	pathDescriptor int
	dataDescriptor int
	parent         *binaryIdentityDirectoryLeaseV1
	name           string
	initial        binaryIdentityObservationV1
	pathFacts      binaryIdentityObjectFactsV1
	expectedMode   uint16
	maximum        uint64
	initialDigest  [sha256.Size]byte
}

func (lease *binaryIdentityFileLeaseV1) close(
	operations binaryIdentityFilesystemOpsV1,
) {
	if lease == nil || operations == nil {
		return
	}
	lease.initial.clear()
	if lease.dataDescriptor >= 0 {
		_ = operations.close(lease.dataDescriptor)
		lease.dataDescriptor = -1
	}
	if lease.pathDescriptor >= 0 {
		_ = operations.close(lease.pathDescriptor)
		lease.pathDescriptor = -1
	}
}

// validateFixedBinaryIdentityFilesystemV1 is intentionally unexported and has
// no production caller. It accepts no caller-selected path, argument,
// environment value or network source. A later reviewed pidfd/systemd
// capability must be the only code allowed to consume its result.
func validateFixedBinaryIdentityFilesystemV1() (binaryIdentityManifestV1, error) {
	return validateFixedBinaryIdentityFilesystemV1WithOps(
		linuxBinaryIdentityFilesystemOpsV1{},
	)
}

func validateFixedBinaryIdentityFilesystemV1WithOps(
	operations binaryIdentityFilesystemOpsV1,
) (binaryIdentityManifestV1, error) {
	if operations == nil {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}

	root, err := openBinaryIdentityRootV1(operations)
	if err != nil {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}
	defer root.close(operations)

	usr, err := openBinaryIdentityDirectoryV1(operations, root, "usr")
	if err != nil {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}
	defer usr.close(operations)

	lib, err := openBinaryIdentityDirectoryV1(operations, usr, "lib")
	if err != nil {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}
	defer lib.close(operations)

	manifestDirectory, err := openBinaryIdentityDirectoryV1(
		operations,
		lib,
		"kyclash",
	)
	if err != nil {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}
	defer manifestDirectory.close(operations)

	executableDirectory, err := openBinaryIdentityDirectoryV1(
		operations,
		usr,
		"libexec",
	)
	if err != nil {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}
	defer executableDirectory.close(operations)

	manifestLease, err := openBinaryIdentityFileV1(
		operations,
		manifestDirectory,
		binaryIdentityManifestFileNameV1,
		binaryIdentityManifestModeV1,
		binaryIdentityManifestMaxSizeV1,
	)
	if err != nil {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}
	defer manifestLease.close(operations)

	encoded, manifestDigest, err := readBinaryIdentityFileV1(
		operations,
		manifestLease.dataDescriptor,
		manifestLease.initial.object.size,
		binaryIdentityManifestMaxSizeV1,
		true,
	)
	if err != nil {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}
	defer clear(encoded)
	manifestLease.initialDigest = manifestDigest
	manifest, err := decodeBinaryIdentityManifestV1(encoded)
	if err != nil {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}
	manifest.manifestSHA256 = manifestDigest

	expectedDigests := [...][sha256.Size]byte{
		manifest.peerSHA256,
		manifest.brokerSHA256,
		manifest.hostBootstrapSHA256,
	}
	executableLeases := make([]*binaryIdentityFileLeaseV1, 0, len(binaryIdentityExecutableNamesV1))
	defer func() {
		for _, lease := range executableLeases {
			lease.close(operations)
		}
	}()
	for index, name := range binaryIdentityExecutableNamesV1 {
		lease, openErr := openBinaryIdentityFileV1(
			operations,
			executableDirectory,
			name,
			binaryIdentityExecutableModeV1,
			binaryIdentityMaxExecutableSizeV1,
		)
		if openErr != nil {
			return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
		}
		executableLeases = append(executableLeases, lease)
		_, digest, readErr := readBinaryIdentityFileV1(
			operations,
			lease.dataDescriptor,
			lease.initial.object.size,
			binaryIdentityMaxExecutableSizeV1,
			false,
		)
		if readErr != nil || digest != expectedDigests[index] {
			return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
		}
		lease.initialDigest = digest
	}

	if verifyBinaryIdentityFileLeaseV1(operations, manifestLease) != nil {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}
	for _, lease := range executableLeases {
		if verifyBinaryIdentityFileLeaseV1(operations, lease) != nil {
			return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
		}
	}

	for _, directory := range []*binaryIdentityDirectoryLeaseV1{
		executableDirectory,
		manifestDirectory,
		lib,
		usr,
		root,
	} {
		if verifyBinaryIdentityDirectoryLeaseV1(operations, directory) != nil {
			return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
		}
	}

	return manifest, nil
}

func openBinaryIdentityRootV1(
	operations binaryIdentityFilesystemOpsV1,
) (*binaryIdentityDirectoryLeaseV1, error) {
	pathDescriptor, err := operations.open("/", binaryIdentityDirectoryPathFlagsV1(), 0)
	if err != nil {
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	lease := &binaryIdentityDirectoryLeaseV1{
		pathDescriptor: pathDescriptor,
		dataDescriptor: -1,
		root:           true,
	}
	complete := false
	defer func() {
		if !complete {
			lease.close(operations)
		}
	}()

	pathFacts, err := captureBinaryIdentityDescriptorFactsV1(operations, pathDescriptor)
	if err != nil || !validBinaryIdentityDirectoryFactsV1(pathFacts) {
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	lease.pathFacts = pathFacts

	dataDescriptor, err := operations.open("/", binaryIdentityDirectoryDataFlagsV1(), 0)
	if err != nil {
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	lease.dataDescriptor = dataDescriptor
	initial, err := observeBinaryIdentityDescriptorV1(operations, dataDescriptor)
	if err != nil ||
		initial.object != pathFacts ||
		!validBinaryIdentityDirectoryObservationV1(initial) {
		initial.clear()
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	lease.initial = initial
	complete = true
	return lease, nil
}

func openBinaryIdentityDirectoryV1(
	operations binaryIdentityFilesystemOpsV1,
	parent *binaryIdentityDirectoryLeaseV1,
	name string,
) (*binaryIdentityDirectoryLeaseV1, error) {
	if operations == nil || parent == nil || !validBinaryIdentityPathComponentV1(name) {
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	pathDescriptor, err := operations.openat2(
		parent.pathDescriptor,
		name,
		&unix.OpenHow{
			Flags:   uint64(binaryIdentityDirectoryPathFlagsV1()),
			Resolve: binaryIdentityResolveFlagsV1(),
		},
	)
	if err != nil {
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	lease := &binaryIdentityDirectoryLeaseV1{
		pathDescriptor: pathDescriptor,
		dataDescriptor: -1,
		parent:         parent,
		name:           name,
	}
	complete := false
	defer func() {
		if !complete {
			lease.close(operations)
		}
	}()

	pathFacts, err := captureBinaryIdentityDescriptorFactsV1(operations, pathDescriptor)
	if err != nil ||
		!validBinaryIdentityDirectoryFactsV1(pathFacts) ||
		!binaryIdentityNamedFactsEqualV1(operations, parent.pathDescriptor, name, pathFacts) {
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	lease.pathFacts = pathFacts

	dataDescriptor, err := operations.openat2(
		parent.pathDescriptor,
		name,
		&unix.OpenHow{
			Flags:   uint64(binaryIdentityDirectoryDataFlagsV1()),
			Resolve: binaryIdentityResolveFlagsV1(),
		},
	)
	if err != nil {
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	lease.dataDescriptor = dataDescriptor
	initial, err := observeBinaryIdentityDescriptorV1(operations, dataDescriptor)
	if err != nil ||
		initial.object != pathFacts ||
		!validBinaryIdentityDirectoryObservationV1(initial) {
		initial.clear()
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	lease.initial = initial
	complete = true
	return lease, nil
}

func openBinaryIdentityFileV1(
	operations binaryIdentityFilesystemOpsV1,
	parent *binaryIdentityDirectoryLeaseV1,
	name string,
	expectedMode uint16,
	maximum uint64,
) (*binaryIdentityFileLeaseV1, error) {
	if operations == nil ||
		parent == nil ||
		!validBinaryIdentityPathComponentV1(name) ||
		(expectedMode != binaryIdentityManifestModeV1 &&
			expectedMode != binaryIdentityExecutableModeV1) ||
		maximum == 0 {
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	pathDescriptor, err := operations.openat2(
		parent.pathDescriptor,
		name,
		&unix.OpenHow{
			Flags:   uint64(binaryIdentityFilePathFlagsV1()),
			Resolve: binaryIdentityResolveFlagsV1(),
		},
	)
	if err != nil {
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	lease := &binaryIdentityFileLeaseV1{
		pathDescriptor: pathDescriptor,
		dataDescriptor: -1,
		parent:         parent,
		name:           name,
		expectedMode:   expectedMode,
		maximum:        maximum,
	}
	complete := false
	defer func() {
		if !complete {
			lease.close(operations)
		}
	}()

	pathFacts, err := captureBinaryIdentityDescriptorFactsV1(operations, pathDescriptor)
	if err != nil ||
		!validBinaryIdentityFileFactsV1(pathFacts, expectedMode, maximum) ||
		!binaryIdentityNamedFactsEqualV1(operations, parent.pathDescriptor, name, pathFacts) {
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	lease.pathFacts = pathFacts

	dataDescriptor, err := operations.openat2(
		parent.pathDescriptor,
		name,
		&unix.OpenHow{
			Flags:   uint64(binaryIdentityFileDataFlagsV1()),
			Resolve: binaryIdentityResolveFlagsV1(),
		},
	)
	if err != nil {
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	lease.dataDescriptor = dataDescriptor
	initial, err := observeBinaryIdentityDescriptorV1(operations, dataDescriptor)
	if err != nil ||
		initial.object != pathFacts ||
		!validBinaryIdentityFileObservationV1(initial, expectedMode, maximum) {
		initial.clear()
		return nil, errBinaryIdentityManifestUnavailableV1
	}
	lease.initial = initial
	complete = true
	return lease, nil
}

func verifyBinaryIdentityDirectoryLeaseV1(
	operations binaryIdentityFilesystemOpsV1,
	lease *binaryIdentityDirectoryLeaseV1,
) error {
	if operations == nil || lease == nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	finalPathFacts, err := captureBinaryIdentityDescriptorFactsV1(
		operations,
		lease.pathDescriptor,
	)
	if err != nil || finalPathFacts != lease.pathFacts {
		return errBinaryIdentityManifestUnavailableV1
	}
	final, err := observeBinaryIdentityDescriptorV1(operations, lease.dataDescriptor)
	if err != nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	defer final.clear()
	if !sameBinaryIdentityObservationV1(lease.initial, final) ||
		!validBinaryIdentityDirectoryObservationV1(final) {
		return errBinaryIdentityManifestUnavailableV1
	}

	if lease.root {
		return verifyReopenedBinaryIdentityRootV1(operations, lease)
	}
	if lease.parent == nil ||
		!binaryIdentityNamedFactsEqualV1(
			operations,
			lease.parent.pathDescriptor,
			lease.name,
			lease.pathFacts,
		) {
		return errBinaryIdentityManifestUnavailableV1
	}
	return verifyReopenedBinaryIdentityDirectoryV1(operations, lease)
}

func verifyReopenedBinaryIdentityRootV1(
	operations binaryIdentityFilesystemOpsV1,
	lease *binaryIdentityDirectoryLeaseV1,
) error {
	pathDescriptor, err := operations.open("/", binaryIdentityDirectoryPathFlagsV1(), 0)
	if err != nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	defer operations.close(pathDescriptor)
	dataDescriptor, err := operations.open("/", binaryIdentityDirectoryDataFlagsV1(), 0)
	if err != nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	defer operations.close(dataDescriptor)
	return compareReopenedBinaryIdentityDirectoryV1(
		operations,
		lease,
		pathDescriptor,
		dataDescriptor,
	)
}

func verifyReopenedBinaryIdentityDirectoryV1(
	operations binaryIdentityFilesystemOpsV1,
	lease *binaryIdentityDirectoryLeaseV1,
) error {
	pathDescriptor, err := operations.openat2(
		lease.parent.pathDescriptor,
		lease.name,
		&unix.OpenHow{
			Flags:   uint64(binaryIdentityDirectoryPathFlagsV1()),
			Resolve: binaryIdentityResolveFlagsV1(),
		},
	)
	if err != nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	defer operations.close(pathDescriptor)
	dataDescriptor, err := operations.openat2(
		lease.parent.pathDescriptor,
		lease.name,
		&unix.OpenHow{
			Flags:   uint64(binaryIdentityDirectoryDataFlagsV1()),
			Resolve: binaryIdentityResolveFlagsV1(),
		},
	)
	if err != nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	defer operations.close(dataDescriptor)
	return compareReopenedBinaryIdentityDirectoryV1(
		operations,
		lease,
		pathDescriptor,
		dataDescriptor,
	)
}

func compareReopenedBinaryIdentityDirectoryV1(
	operations binaryIdentityFilesystemOpsV1,
	lease *binaryIdentityDirectoryLeaseV1,
	pathDescriptor int,
	dataDescriptor int,
) error {
	pathFacts, err := captureBinaryIdentityDescriptorFactsV1(operations, pathDescriptor)
	if err != nil || pathFacts != lease.pathFacts {
		return errBinaryIdentityManifestUnavailableV1
	}
	observation, err := observeBinaryIdentityDescriptorV1(operations, dataDescriptor)
	if err != nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	defer observation.clear()
	if !sameBinaryIdentityObservationV1(lease.initial, observation) ||
		!validBinaryIdentityDirectoryObservationV1(observation) {
		return errBinaryIdentityManifestUnavailableV1
	}
	return nil
}

func verifyBinaryIdentityFileLeaseV1(
	operations binaryIdentityFilesystemOpsV1,
	lease *binaryIdentityFileLeaseV1,
) error {
	if operations == nil || lease == nil || lease.parent == nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	finalPathFacts, err := captureBinaryIdentityDescriptorFactsV1(
		operations,
		lease.pathDescriptor,
	)
	if err != nil || finalPathFacts != lease.pathFacts {
		return errBinaryIdentityManifestUnavailableV1
	}
	final, err := observeBinaryIdentityDescriptorV1(operations, lease.dataDescriptor)
	if err != nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	defer final.clear()
	if !sameBinaryIdentityObservationV1(lease.initial, final) ||
		!validBinaryIdentityFileObservationV1(final, lease.expectedMode, lease.maximum) ||
		!binaryIdentityNamedFactsEqualV1(
			operations,
			lease.parent.pathDescriptor,
			lease.name,
			lease.pathFacts,
		) {
		return errBinaryIdentityManifestUnavailableV1
	}

	pathDescriptor, err := operations.openat2(
		lease.parent.pathDescriptor,
		lease.name,
		&unix.OpenHow{
			Flags:   uint64(binaryIdentityFilePathFlagsV1()),
			Resolve: binaryIdentityResolveFlagsV1(),
		},
	)
	if err != nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	defer operations.close(pathDescriptor)
	reopenedPathFacts, err := captureBinaryIdentityDescriptorFactsV1(
		operations,
		pathDescriptor,
	)
	if err != nil || reopenedPathFacts != lease.pathFacts {
		return errBinaryIdentityManifestUnavailableV1
	}

	dataDescriptor, err := operations.openat2(
		lease.parent.pathDescriptor,
		lease.name,
		&unix.OpenHow{
			Flags:   uint64(binaryIdentityFileDataFlagsV1()),
			Resolve: binaryIdentityResolveFlagsV1(),
		},
	)
	if err != nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	defer operations.close(dataDescriptor)
	reopened, err := observeBinaryIdentityDescriptorV1(operations, dataDescriptor)
	if err != nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	defer reopened.clear()
	if !sameBinaryIdentityObservationV1(lease.initial, reopened) ||
		!validBinaryIdentityFileObservationV1(
			reopened,
			lease.expectedMode,
			lease.maximum,
		) {
		return errBinaryIdentityManifestUnavailableV1
	}

	_, digest, err := readBinaryIdentityFileV1(
		operations,
		dataDescriptor,
		reopened.object.size,
		lease.maximum,
		false,
	)
	if err != nil || digest != lease.initialDigest {
		return errBinaryIdentityManifestUnavailableV1
	}
	afterDigest, err := observeBinaryIdentityDescriptorV1(operations, dataDescriptor)
	if err != nil {
		return errBinaryIdentityManifestUnavailableV1
	}
	defer afterDigest.clear()
	if !sameBinaryIdentityObservationV1(reopened, afterDigest) ||
		!binaryIdentityNamedFactsEqualV1(
			operations,
			lease.parent.pathDescriptor,
			lease.name,
			lease.pathFacts,
		) {
		return errBinaryIdentityManifestUnavailableV1
	}
	return nil
}

func observeBinaryIdentityDescriptorV1(
	operations binaryIdentityFilesystemOpsV1,
	descriptor int,
) (result binaryIdentityObservationV1, resultErr error) {
	object, err := captureBinaryIdentityDescriptorFactsV1(operations, descriptor)
	if err != nil {
		return binaryIdentityObservationV1{}, errBinaryIdentityManifestUnavailableV1
	}
	result.object = object
	result.accessACL, err = operations.readXattr(descriptor, binaryIdentityACLAccessXattrV1)
	if err != nil {
		result.clear()
		return binaryIdentityObservationV1{}, errBinaryIdentityManifestUnavailableV1
	}
	result.defaultACL, err = operations.readXattr(descriptor, binaryIdentityACLDefaultXattrV1)
	if err != nil {
		result.clear()
		return binaryIdentityObservationV1{}, errBinaryIdentityManifestUnavailableV1
	}
	result.capabilities, err = operations.readXattr(descriptor, binaryIdentityCapabilityXattrV1)
	if err != nil {
		result.clear()
		return binaryIdentityObservationV1{}, errBinaryIdentityManifestUnavailableV1
	}
	return result, nil
}

func captureBinaryIdentityDescriptorFactsV1(
	operations binaryIdentityFilesystemOpsV1,
	descriptor int,
) (binaryIdentityObjectFactsV1, error) {
	var raw unix.Statx_t
	if err := operations.statx(
		descriptor,
		"",
		unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW,
		binaryIdentityStatxMaskV1(),
		&raw,
	); err != nil {
		return binaryIdentityObjectFactsV1{}, errBinaryIdentityManifestUnavailableV1
	}
	return normalizeBinaryIdentityObjectFactsV1(&raw)
}

func captureBinaryIdentityNamedFactsV1(
	operations binaryIdentityFilesystemOpsV1,
	parentDescriptor int,
	name string,
) (binaryIdentityObjectFactsV1, error) {
	if !validBinaryIdentityPathComponentV1(name) {
		return binaryIdentityObjectFactsV1{}, errBinaryIdentityManifestUnavailableV1
	}
	var raw unix.Statx_t
	if err := operations.statx(
		parentDescriptor,
		name,
		unix.AT_SYMLINK_NOFOLLOW,
		binaryIdentityStatxMaskV1(),
		&raw,
	); err != nil {
		return binaryIdentityObjectFactsV1{}, errBinaryIdentityManifestUnavailableV1
	}
	return normalizeBinaryIdentityObjectFactsV1(&raw)
}

func normalizeBinaryIdentityObjectFactsV1(
	raw *unix.Statx_t,
) (binaryIdentityObjectFactsV1, error) {
	requiredMask := uint32(binaryIdentityStatxMaskV1())
	if raw == nil ||
		raw.Mask&requiredMask != requiredMask ||
		raw.Mnt_id == 0 ||
		raw.Nlink == 0 {
		return binaryIdentityObjectFactsV1{}, errBinaryIdentityManifestUnavailableV1
	}
	return binaryIdentityObjectFactsV1{
		mask:           raw.Mask & requiredMask,
		attributes:     raw.Attributes & raw.Attributes_mask,
		attributesMask: raw.Attributes_mask,
		nlink:          raw.Nlink,
		uid:            raw.Uid,
		gid:            raw.Gid,
		mode:           raw.Mode,
		inode:          raw.Ino,
		size:           raw.Size,
		blocks:         raw.Blocks,
		ctimeSeconds:   raw.Ctime.Sec,
		ctimeNanos:     raw.Ctime.Nsec,
		mtimeSeconds:   raw.Mtime.Sec,
		mtimeNanos:     raw.Mtime.Nsec,
		deviceMajor:    raw.Dev_major,
		deviceMinor:    raw.Dev_minor,
		mountID:        raw.Mnt_id,
	}, nil
}

func binaryIdentityNamedFactsEqualV1(
	operations binaryIdentityFilesystemOpsV1,
	parentDescriptor int,
	name string,
	expected binaryIdentityObjectFactsV1,
) bool {
	actual, err := captureBinaryIdentityNamedFactsV1(
		operations,
		parentDescriptor,
		name,
	)
	return err == nil && actual == expected
}

func validBinaryIdentityDirectoryFactsV1(facts binaryIdentityObjectFactsV1) bool {
	return facts.mode&unix.S_IFMT == unix.S_IFDIR &&
		facts.uid == 0 &&
		facts.gid == 0 &&
		facts.mode&0o022 == 0 &&
		facts.nlink != 0
}

func validBinaryIdentityDirectoryObservationV1(
	observation binaryIdentityObservationV1,
) bool {
	return validBinaryIdentityDirectoryFactsV1(observation.object) &&
		binaryIdentityXattrsAbsentV1(observation)
}

func validBinaryIdentityFileFactsV1(
	facts binaryIdentityObjectFactsV1,
	expectedMode uint16,
	maximum uint64,
) bool {
	return facts.mode == expectedMode &&
		facts.uid == 0 &&
		facts.gid == 0 &&
		facts.nlink == 1 &&
		facts.size > 0 &&
		facts.size <= maximum
}

func validBinaryIdentityFileObservationV1(
	observation binaryIdentityObservationV1,
	expectedMode uint16,
	maximum uint64,
) bool {
	return validBinaryIdentityFileFactsV1(observation.object, expectedMode, maximum) &&
		binaryIdentityXattrsAbsentV1(observation)
}

func binaryIdentityXattrsAbsentV1(observation binaryIdentityObservationV1) bool {
	return !observation.accessACL.present &&
		len(observation.accessACL.encoded) == 0 &&
		!observation.defaultACL.present &&
		len(observation.defaultACL.encoded) == 0 &&
		!observation.capabilities.present &&
		len(observation.capabilities.encoded) == 0
}

func sameBinaryIdentityObservationV1(
	left binaryIdentityObservationV1,
	right binaryIdentityObservationV1,
) bool {
	return left.object == right.object &&
		left.accessACL.present == right.accessACL.present &&
		bytesEqualBinaryIdentityV1(left.accessACL.encoded, right.accessACL.encoded) &&
		left.defaultACL.present == right.defaultACL.present &&
		bytesEqualBinaryIdentityV1(left.defaultACL.encoded, right.defaultACL.encoded) &&
		left.capabilities.present == right.capabilities.present &&
		bytesEqualBinaryIdentityV1(
			left.capabilities.encoded,
			right.capabilities.encoded,
		)
}

func bytesEqualBinaryIdentityV1(left []byte, right []byte) bool {
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

func readBinaryIdentityFileV1(
	operations binaryIdentityFilesystemOpsV1,
	descriptor int,
	size uint64,
	maximum uint64,
	retain bool,
) ([]byte, [sha256.Size]byte, error) {
	if operations == nil || size == 0 || size > maximum {
		return nil, [sha256.Size]byte{}, errBinaryIdentityManifestUnavailableV1
	}
	digest := sha256.New()
	var retained []byte
	if retain {
		retained = make([]byte, int(size))
	}
	var buffer [binaryIdentityReadBufferSizeV1]byte
	defer clear(buffer[:])

	var offset uint64
	for offset < size {
		remaining := size - offset
		length := uint64(len(buffer))
		if remaining < length {
			length = remaining
		}
		destination := buffer[:int(length)]
		count, err := operations.pread(descriptor, destination, int64(offset))
		if err != nil {
			if errors.Is(err, unix.EINTR) && count == 0 {
				continue
			}
			clear(retained)
			return nil, [sha256.Size]byte{}, errBinaryIdentityManifestUnavailableV1
		}
		if count <= 0 || count > len(destination) {
			clear(retained)
			return nil, [sha256.Size]byte{}, errBinaryIdentityManifestUnavailableV1
		}
		if _, err := digest.Write(destination[:count]); err != nil {
			clear(retained)
			return nil, [sha256.Size]byte{}, errBinaryIdentityManifestUnavailableV1
		}
		if retain {
			copy(retained[int(offset):], destination[:count])
		}
		offset += uint64(count)
	}

	var probe [1]byte
	defer clear(probe[:])
	for {
		count, err := operations.pread(descriptor, probe[:], int64(size))
		if err != nil {
			if errors.Is(err, unix.EINTR) && count == 0 {
				continue
			}
			clear(retained)
			return nil, [sha256.Size]byte{}, errBinaryIdentityManifestUnavailableV1
		}
		if count != 0 {
			clear(retained)
			return nil, [sha256.Size]byte{}, errBinaryIdentityManifestUnavailableV1
		}
		break
	}
	return retained, digestSumBinaryIdentityV1(digest), nil
}

func digestSumBinaryIdentityV1(digest hash.Hash) [sha256.Size]byte {
	var result [sha256.Size]byte
	if digest == nil {
		return result
	}
	sum := digest.Sum(nil)
	copy(result[:], sum)
	clear(sum)
	return result
}

func binaryIdentityStatxMaskV1() int {
	return unix.STATX_TYPE |
		unix.STATX_MODE |
		unix.STATX_NLINK |
		unix.STATX_UID |
		unix.STATX_GID |
		unix.STATX_INO |
		unix.STATX_SIZE |
		unix.STATX_BLOCKS |
		unix.STATX_MTIME |
		unix.STATX_CTIME |
		unix.STATX_MNT_ID
}

func binaryIdentityResolveFlagsV1() uint64 {
	return unix.RESOLVE_BENEATH |
		unix.RESOLVE_NO_SYMLINKS |
		unix.RESOLVE_NO_MAGICLINKS
}

func binaryIdentityDirectoryPathFlagsV1() int {
	return unix.O_PATH |
		unix.O_DIRECTORY |
		unix.O_CLOEXEC |
		unix.O_NOFOLLOW
}

func binaryIdentityDirectoryDataFlagsV1() int {
	return unix.O_RDONLY |
		unix.O_DIRECTORY |
		unix.O_CLOEXEC |
		unix.O_NOFOLLOW |
		unix.O_NONBLOCK
}

func binaryIdentityFilePathFlagsV1() int {
	return unix.O_PATH |
		unix.O_CLOEXEC |
		unix.O_NOFOLLOW
}

func binaryIdentityFileDataFlagsV1() int {
	return unix.O_RDONLY |
		unix.O_CLOEXEC |
		unix.O_NOFOLLOW |
		unix.O_NONBLOCK
}

func validBinaryIdentityPathComponentV1(component string) bool {
	if component == "" || component == "." || component == ".." {
		return false
	}
	for index := range component {
		if component[index] == 0 || component[index] == '/' {
			return false
		}
	}
	return true
}
