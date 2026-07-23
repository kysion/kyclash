//go:build linux

package productionpeer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	systemdCredentialAccessACLXattr  = "system.posix_acl_access"
	systemdCredentialDefaultACLXattr = "system.posix_acl_default"
	systemdCredentialMaxACLSize      = 4096

	systemdCredentialDirectoryRootACLMode = unix.S_IFDIR | 0o550
	systemdCredentialFileRootACLMode      = unix.S_IFREG | 0o440
	systemdCredentialDirectoryOwnerMode   = unix.S_IFDIR | 0o500
	systemdCredentialFileOwnerMode        = unix.S_IFREG | 0o400

	systemdCredentialMountSecurityFlags = unix.ST_RDONLY |
		unix.ST_NODEV |
		unix.ST_NOSUID |
		unix.ST_NOEXEC
)

var systemdCredentialSpecsV2 = [...]systemdCredentialSpecV2{
	{name: TLSCertificateCredentialName, maximum: MaxTLSCertificateCredentialSize},
	{name: TLSPrivateKeyCredentialName, maximum: MaxTLSPrivateKeyCredentialSize},
	{name: WireGuardPrivateCredentialName, maximum: MaxWireGuardPrivateCredentialSize},
}

type systemdCredentialSpecV2 struct {
	name    string
	maximum int
}

type systemdCredentialMaterializationProfileV2 uint8

const (
	systemdCredentialMaterializationInvalidV2 systemdCredentialMaterializationProfileV2 = iota
	systemdCredentialMaterializationRootACLV2
	systemdCredentialMaterializationPeerOwnedReadOnlyV2
)

// systemdCredentialFileSetV2 owns fixed-capacity buffers for exactly the three
// reviewed systemd credentials. It is deliberately not connected to the
// public loader: a later invocation-identity capability must be the only live
// caller. Close clears each complete backing allocation, not merely its
// currently visible length.
type systemdCredentialFileSetV2 struct {
	tlsCertificatePEM   []byte
	tlsPrivateKeyPEM    []byte
	wireGuardPrivateKey []byte
}

const systemdCredentialFileSetRedactedV2 = "systemdCredentialFileSetV2{TLSCertificate:<redacted> TLSPrivateKey:<redacted> WireGuardPrivateKey:<redacted>}"

func (systemdCredentialFileSetV2) String() string {
	return systemdCredentialFileSetRedactedV2
}

func (systemdCredentialFileSetV2) GoString() string {
	return systemdCredentialFileSetRedactedV2
}

func (systemdCredentialFileSetV2) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, systemdCredentialFileSetRedactedV2)
}

func (set *systemdCredentialFileSetV2) Close() {
	if set == nil {
		return
	}
	clearCredentialAllocationV2(set.tlsCertificatePEM)
	clearCredentialAllocationV2(set.tlsPrivateKeyPEM)
	clearCredentialAllocationV2(set.wireGuardPrivateKey)
	set.tlsCertificatePEM = nil
	set.tlsPrivateKeyPEM = nil
	set.wireGuardPrivateKey = nil
}

func clearCredentialAllocationV2(encoded []byte) {
	if cap(encoded) == 0 {
		return
	}
	clear(encoded[:cap(encoded)])
}

type systemdCredentialObjectFactsV2 struct {
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

type systemdCredentialMountFactsV2 struct {
	filesystemType int64
	flags          uint64
	fsid           [2]int32
}

type systemdCredentialXattrV2 struct {
	present bool
	encoded []byte
}

func (attribute *systemdCredentialXattrV2) clear() {
	if attribute == nil {
		return
	}
	clearCredentialAllocationV2(attribute.encoded)
	attribute.encoded = nil
	attribute.present = false
}

type systemdCredentialObservationV2 struct {
	object     systemdCredentialObjectFactsV2
	mount      systemdCredentialMountFactsV2
	accessACL  systemdCredentialXattrV2
	defaultACL systemdCredentialXattrV2
}

func (observation *systemdCredentialObservationV2) clear() {
	if observation == nil {
		return
	}
	observation.accessACL.clear()
	observation.defaultACL.clear()
}

// systemdCredentialFilesystemOpsV2 is an unexported all-or-nothing test seam.
// Production always uses linuxSystemdCredentialFilesystemOpsV2. Synthetic
// tests can model materialization shapes and races without reading a real
// CREDENTIALS_DIRECTORY or weakening the public fail-closed loader.
type systemdCredentialFilesystemOpsV2 interface {
	open(path string, flags int, mode uint32) (int, error)
	openat2(directoryDescriptor int, path string, how *unix.OpenHow) (int, error)
	close(descriptor int) error
	statx(directoryDescriptor int, path string, flags int, mask int, facts *unix.Statx_t) error
	fstatfs(descriptor int, facts *unix.Statfs_t) error
	readDirectoryNames(context.Context, int) ([]string, error)
	readXattr(int, string) (systemdCredentialXattrV2, error)
	pread(int, []byte, int64) (int, error)
}

type linuxSystemdCredentialFilesystemOpsV2 struct{}

func (linuxSystemdCredentialFilesystemOpsV2) open(path string, flags int, mode uint32) (int, error) {
	return unix.Open(path, flags, mode)
}

func (linuxSystemdCredentialFilesystemOpsV2) openat2(
	directoryDescriptor int,
	path string,
	how *unix.OpenHow,
) (int, error) {
	return unix.Openat2(directoryDescriptor, path, how)
}

func (linuxSystemdCredentialFilesystemOpsV2) close(descriptor int) error {
	return unix.Close(descriptor)
}

func (linuxSystemdCredentialFilesystemOpsV2) statx(
	directoryDescriptor int,
	path string,
	flags int,
	mask int,
	facts *unix.Statx_t,
) error {
	return unix.Statx(directoryDescriptor, path, flags, mask, facts)
}

func (linuxSystemdCredentialFilesystemOpsV2) fstatfs(
	descriptor int,
	facts *unix.Statfs_t,
) error {
	return unix.Fstatfs(descriptor, facts)
}

func (linuxSystemdCredentialFilesystemOpsV2) pread(
	descriptor int,
	destination []byte,
	offset int64,
) (int, error) {
	return unix.Pread(descriptor, destination, offset)
}

func (linuxSystemdCredentialFilesystemOpsV2) readDirectoryNames(
	ctx context.Context,
	descriptor int,
) ([]string, error) {
	if credentialContextDoneV2(ctx) {
		return nil, ErrCredentialUnavailable
	}
	if _, err := unix.Seek(descriptor, 0, 0); err != nil {
		return nil, ErrCredentialUnavailable
	}

	var buffer [4096]byte
	names := make([]string, 0, len(systemdCredentialSpecsV2)+1)
	for {
		if credentialContextDoneV2(ctx) {
			return nil, ErrCredentialUnavailable
		}
		count, err := unix.ReadDirent(descriptor, buffer[:])
		if err != nil {
			return nil, ErrCredentialUnavailable
		}
		if count == 0 {
			break
		}
		_, _, names = unix.ParseDirent(
			buffer[:count],
			len(systemdCredentialSpecsV2)+1-len(names),
			names,
		)
		if len(names) > len(systemdCredentialSpecsV2) {
			return nil, ErrCredentialUnavailable
		}
	}
	sort.Strings(names)
	return names, nil
}

func (linuxSystemdCredentialFilesystemOpsV2) readXattr(
	descriptor int,
	name string,
) (result systemdCredentialXattrV2, err error) {
	var encoded [systemdCredentialMaxACLSize]byte
	defer clear(encoded[:])

	length, err := unix.Fgetxattr(descriptor, name, encoded[:])
	switch {
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOTSUP):
		return systemdCredentialXattrV2{}, nil
	case err != nil, length < 0, length > len(encoded):
		return systemdCredentialXattrV2{}, ErrCredentialUnavailable
	}
	result.present = true
	result.encoded = make([]byte, length)
	copy(result.encoded, encoded[:length])
	return result, nil
}

// readSystemdCredentialFilesystemV2 is intentionally unexported and currently
// has no production caller. Passing a directory here is not an invocation
// proof; the later live loader must first seal the exact unit/invocation
// identity and PR_SET_DUMPABLE=0 into its one-use capability.
func readSystemdCredentialFilesystemV2(
	ctx context.Context,
	directory string,
	peerUID uint32,
) (*systemdCredentialFileSetV2, error) {
	return readSystemdCredentialFilesystemV2WithOps(
		ctx,
		directory,
		peerUID,
		linuxSystemdCredentialFilesystemOpsV2{},
	)
}

func readSystemdCredentialFilesystemV2WithOps(
	ctx context.Context,
	directory string,
	peerUID uint32,
	operations systemdCredentialFilesystemOpsV2,
) (result *systemdCredentialFileSetV2, resultErr error) {
	if operations == nil ||
		credentialContextDoneV2(ctx) ||
		!canonicalSystemdCredentialDirectoryV2(directory) ||
		peerUID == 0 ||
		peerUID == systemdCredentialACLUndefinedID {
		return nil, ErrCredentialUnavailable
	}

	rootDescriptor, err := operations.open(
		"/",
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	defer operations.close(rootDescriptor)

	relativeDirectory := strings.TrimPrefix(directory, "/")
	resolve := uint64(
		unix.RESOLVE_BENEATH |
			unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS,
	)
	pathDescriptor, err := operations.openat2(rootDescriptor, relativeDirectory, &unix.OpenHow{
		Flags: uint64(
			unix.O_PATH |
				unix.O_DIRECTORY |
				unix.O_CLOEXEC |
				unix.O_NOFOLLOW,
		),
		Resolve: resolve,
	})
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	defer operations.close(pathDescriptor)

	directoryDescriptor, err := operations.openat2(rootDescriptor, relativeDirectory, &unix.OpenHow{
		Flags: uint64(
			unix.O_RDONLY |
				unix.O_DIRECTORY |
				unix.O_CLOEXEC |
				unix.O_NOFOLLOW |
				unix.O_NONBLOCK,
		),
		Resolve: resolve,
	})
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	defer operations.close(directoryDescriptor)

	pathFacts, pathMount, err := captureSystemdCredentialDescriptorFactsV2(
		operations,
		pathDescriptor,
	)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	initialDirectory, err := observeSystemdCredentialDescriptorV2(
		operations,
		directoryDescriptor,
	)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	defer initialDirectory.clear()
	if !sameSystemdCredentialObjectFactsV2(pathFacts, initialDirectory.object) ||
		pathMount != initialDirectory.mount {
		return nil, ErrCredentialUnavailable
	}

	profile := classifySystemdCredentialObservationV2(
		initialDirectory,
		peerUID,
		true,
		0,
	)
	if profile == systemdCredentialMaterializationInvalidV2 {
		return nil, ErrCredentialUnavailable
	}
	if credentialContextDoneV2(ctx) {
		return nil, ErrCredentialUnavailable
	}

	initialNames, err := operations.readDirectoryNames(ctx, directoryDescriptor)
	if err != nil || !exactSystemdCredentialNamesV2(initialNames) {
		return nil, ErrCredentialUnavailable
	}

	result = &systemdCredentialFileSetV2{}
	ownedResult := result
	complete := false
	defer func() {
		if !complete {
			ownedResult.Close()
			result = nil
			resultErr = ErrCredentialUnavailable
		}
	}()

	for _, specification := range systemdCredentialSpecsV2 {
		if credentialContextDoneV2(ctx) {
			return nil, ErrCredentialUnavailable
		}
		encoded, readErr := readOneSystemdCredentialV2(
			ctx,
			operations,
			directoryDescriptor,
			specification,
			peerUID,
			profile,
		)
		if readErr != nil {
			return nil, ErrCredentialUnavailable
		}
		switch specification.name {
		case TLSCertificateCredentialName:
			result.tlsCertificatePEM = encoded
		case TLSPrivateKeyCredentialName:
			result.tlsPrivateKeyPEM = encoded
		case WireGuardPrivateCredentialName:
			result.wireGuardPrivateKey = encoded
		default:
			clearCredentialAllocationV2(encoded)
			return nil, ErrCredentialUnavailable
		}
	}

	if credentialContextDoneV2(ctx) {
		return nil, ErrCredentialUnavailable
	}
	finalNames, err := operations.readDirectoryNames(ctx, directoryDescriptor)
	if err != nil ||
		!exactSystemdCredentialNamesV2(finalNames) ||
		!sameSystemdCredentialNamesV2(initialNames, finalNames) {
		return nil, ErrCredentialUnavailable
	}

	finalDirectory, err := observeSystemdCredentialDescriptorV2(
		operations,
		directoryDescriptor,
	)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	defer finalDirectory.clear()
	finalPathFacts, finalPathMount, err := captureSystemdCredentialDescriptorFactsV2(
		operations,
		pathDescriptor,
	)
	reopenedPathFacts, reopenedPathMount, reopenErr := reopenSystemdCredentialDirectoryPathV2(
		operations,
		rootDescriptor,
		relativeDirectory,
		resolve,
	)
	if err != nil ||
		reopenErr != nil ||
		!sameSystemdCredentialObservationV2(initialDirectory, finalDirectory) ||
		classifySystemdCredentialObservationV2(finalDirectory, peerUID, true, 0) != profile ||
		!sameSystemdCredentialObjectFactsV2(pathFacts, finalPathFacts) ||
		pathMount != finalPathMount ||
		!sameSystemdCredentialObjectFactsV2(finalPathFacts, finalDirectory.object) ||
		finalPathMount != finalDirectory.mount ||
		!sameSystemdCredentialObjectFactsV2(pathFacts, reopenedPathFacts) ||
		pathMount != reopenedPathMount ||
		credentialContextDoneV2(ctx) {
		return nil, ErrCredentialUnavailable
	}

	complete = true
	return result, nil
}

func reopenSystemdCredentialDirectoryPathV2(
	operations systemdCredentialFilesystemOpsV2,
	rootDescriptor int,
	relativeDirectory string,
	resolve uint64,
) (systemdCredentialObjectFactsV2, systemdCredentialMountFactsV2, error) {
	reopenedDescriptor, err := operations.openat2(rootDescriptor, relativeDirectory, &unix.OpenHow{
		Flags: uint64(
			unix.O_PATH |
				unix.O_DIRECTORY |
				unix.O_CLOEXEC |
				unix.O_NOFOLLOW,
		),
		Resolve: resolve,
	})
	if err != nil {
		return systemdCredentialObjectFactsV2{}, systemdCredentialMountFactsV2{}, ErrCredentialUnavailable
	}
	defer operations.close(reopenedDescriptor)
	return captureSystemdCredentialDescriptorFactsV2(operations, reopenedDescriptor)
}

func readOneSystemdCredentialV2(
	ctx context.Context,
	operations systemdCredentialFilesystemOpsV2,
	directoryDescriptor int,
	specification systemdCredentialSpecV2,
	peerUID uint32,
	expectedProfile systemdCredentialMaterializationProfileV2,
) (encoded []byte, resultErr error) {
	if !validCredentialName(specification.name) ||
		specification.maximum <= 0 ||
		credentialContextDoneV2(ctx) {
		return nil, ErrCredentialUnavailable
	}

	resolve := uint64(
		unix.RESOLVE_BENEATH |
			unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS,
	)
	pathDescriptor, err := operations.openat2(directoryDescriptor, specification.name, &unix.OpenHow{
		Flags: uint64(
			unix.O_PATH |
				unix.O_CLOEXEC |
				unix.O_NOFOLLOW,
		),
		Resolve: resolve,
	})
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	defer operations.close(pathDescriptor)

	pathFacts, pathMount, err := captureSystemdCredentialDescriptorFactsV2(
		operations,
		pathDescriptor,
	)
	if err != nil ||
		pathFacts.mode&unix.S_IFMT != unix.S_IFREG ||
		pathFacts.nlink != 1 ||
		pathFacts.size == 0 ||
		pathFacts.size > uint64(specification.maximum) {
		return nil, ErrCredentialUnavailable
	}

	readDescriptor, err := operations.openat2(directoryDescriptor, specification.name, &unix.OpenHow{
		Flags: uint64(
			unix.O_RDONLY |
				unix.O_CLOEXEC |
				unix.O_NOFOLLOW |
				unix.O_NONBLOCK,
		),
		Resolve: resolve,
	})
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	defer operations.close(readDescriptor)

	initial, err := observeSystemdCredentialDescriptorV2(operations, readDescriptor)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	defer initial.clear()
	namedFacts, err := captureSystemdCredentialNamedFactsV2(
		operations,
		directoryDescriptor,
		specification.name,
	)
	if err != nil ||
		!sameSystemdCredentialObjectFactsV2(pathFacts, initial.object) ||
		pathMount != initial.mount ||
		!sameSystemdCredentialObjectFactsV2(pathFacts, namedFacts) ||
		classifySystemdCredentialObservationV2(
			initial,
			peerUID,
			false,
			specification.maximum,
		) != expectedProfile {
		return nil, ErrCredentialUnavailable
	}

	encoded, err = readBoundedSystemdCredentialV2(
		ctx,
		operations,
		readDescriptor,
		int(initial.object.size),
		specification.maximum,
	)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	ownedEncoded := encoded
	complete := false
	defer func() {
		if !complete {
			clearCredentialAllocationV2(ownedEncoded)
			encoded = nil
			resultErr = ErrCredentialUnavailable
		}
	}()

	if credentialContextDoneV2(ctx) {
		return nil, ErrCredentialUnavailable
	}
	final, err := observeSystemdCredentialDescriptorV2(operations, readDescriptor)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	defer final.clear()
	finalPathFacts, finalPathMount, err := captureSystemdCredentialDescriptorFactsV2(
		operations,
		pathDescriptor,
	)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	finalNamedFacts, err := captureSystemdCredentialNamedFactsV2(
		operations,
		directoryDescriptor,
		specification.name,
	)
	if err != nil ||
		!sameSystemdCredentialObservationV2(initial, final) ||
		classifySystemdCredentialObservationV2(
			final,
			peerUID,
			false,
			specification.maximum,
		) != expectedProfile ||
		!sameSystemdCredentialObjectFactsV2(pathFacts, finalPathFacts) ||
		pathMount != finalPathMount ||
		!sameSystemdCredentialObjectFactsV2(pathFacts, finalNamedFacts) ||
		uint64(len(encoded)) != initial.object.size ||
		credentialContextDoneV2(ctx) {
		return nil, ErrCredentialUnavailable
	}

	complete = true
	return encoded, nil
}

func readBoundedSystemdCredentialV2(
	ctx context.Context,
	operations systemdCredentialFilesystemOpsV2,
	descriptor int,
	size int,
	maximum int,
) ([]byte, error) {
	if operations == nil ||
		size <= 0 ||
		size > maximum ||
		maximum <= 0 ||
		credentialContextDoneV2(ctx) {
		return nil, ErrCredentialUnavailable
	}
	storage := make([]byte, maximum)
	complete := false
	defer func() {
		if !complete {
			clear(storage)
		}
	}()

	offset := 0
	for offset < size {
		if credentialContextDoneV2(ctx) {
			return nil, ErrCredentialUnavailable
		}
		count, err := operations.pread(
			descriptor,
			storage[offset:size],
			int64(offset),
		)
		if err != nil {
			if errors.Is(err, unix.EINTR) && count == 0 {
				continue
			}
			return nil, ErrCredentialUnavailable
		}
		if count <= 0 || count > size-offset {
			return nil, ErrCredentialUnavailable
		}
		offset += count
	}

	var probe [1]byte
	defer clear(probe[:])
	for {
		if credentialContextDoneV2(ctx) {
			return nil, ErrCredentialUnavailable
		}
		count, err := operations.pread(descriptor, probe[:], int64(size))
		if err != nil {
			if errors.Is(err, unix.EINTR) && count == 0 {
				continue
			}
			return nil, ErrCredentialUnavailable
		}
		if count != 0 {
			return nil, ErrCredentialUnavailable
		}
		break
	}
	if bytes.IndexByte(storage[:size], 0) >= 0 {
		return nil, ErrCredentialUnavailable
	}

	complete = true
	return storage[:size], nil
}

func observeSystemdCredentialDescriptorV2(
	operations systemdCredentialFilesystemOpsV2,
	descriptor int,
) (result systemdCredentialObservationV2, resultErr error) {
	object, mount, err := captureSystemdCredentialDescriptorFactsV2(operations, descriptor)
	if err != nil {
		return systemdCredentialObservationV2{}, ErrCredentialUnavailable
	}
	result.object = object
	result.mount = mount
	result.accessACL, err = operations.readXattr(descriptor, systemdCredentialAccessACLXattr)
	if err != nil {
		result.clear()
		return systemdCredentialObservationV2{}, ErrCredentialUnavailable
	}
	result.defaultACL, err = operations.readXattr(descriptor, systemdCredentialDefaultACLXattr)
	if err != nil {
		result.clear()
		return systemdCredentialObservationV2{}, ErrCredentialUnavailable
	}
	return result, nil
}

func captureSystemdCredentialDescriptorFactsV2(
	operations systemdCredentialFilesystemOpsV2,
	descriptor int,
) (systemdCredentialObjectFactsV2, systemdCredentialMountFactsV2, error) {
	var rawObject unix.Statx_t
	if err := operations.statx(
		descriptor,
		"",
		unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW,
		systemdCredentialStatxMaskV2(),
		&rawObject,
	); err != nil {
		return systemdCredentialObjectFactsV2{}, systemdCredentialMountFactsV2{}, ErrCredentialUnavailable
	}
	object, valid := normalizeSystemdCredentialObjectFactsV2(&rawObject)
	if !valid {
		return systemdCredentialObjectFactsV2{}, systemdCredentialMountFactsV2{}, ErrCredentialUnavailable
	}

	var rawMount unix.Statfs_t
	if err := operations.fstatfs(descriptor, &rawMount); err != nil {
		return systemdCredentialObjectFactsV2{}, systemdCredentialMountFactsV2{}, ErrCredentialUnavailable
	}
	return object, normalizeSystemdCredentialMountFactsV2(&rawMount), nil
}

func captureSystemdCredentialNamedFactsV2(
	operations systemdCredentialFilesystemOpsV2,
	directoryDescriptor int,
	name string,
) (systemdCredentialObjectFactsV2, error) {
	if !validCredentialName(name) {
		return systemdCredentialObjectFactsV2{}, ErrCredentialUnavailable
	}
	var raw unix.Statx_t
	if err := operations.statx(
		directoryDescriptor,
		name,
		unix.AT_SYMLINK_NOFOLLOW,
		systemdCredentialStatxMaskV2(),
		&raw,
	); err != nil {
		return systemdCredentialObjectFactsV2{}, ErrCredentialUnavailable
	}
	normalized, valid := normalizeSystemdCredentialObjectFactsV2(&raw)
	if !valid {
		return systemdCredentialObjectFactsV2{}, ErrCredentialUnavailable
	}
	return normalized, nil
}

func systemdCredentialStatxMaskV2() int {
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

func normalizeSystemdCredentialObjectFactsV2(
	raw *unix.Statx_t,
) (systemdCredentialObjectFactsV2, bool) {
	requiredMask := uint32(systemdCredentialStatxMaskV2())
	if raw == nil ||
		raw.Mask&requiredMask != requiredMask ||
		raw.Mnt_id == 0 {
		return systemdCredentialObjectFactsV2{}, false
	}
	return systemdCredentialObjectFactsV2{
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
	}, true
}

func normalizeSystemdCredentialMountFactsV2(
	raw *unix.Statfs_t,
) systemdCredentialMountFactsV2 {
	if raw == nil {
		return systemdCredentialMountFactsV2{}
	}
	return systemdCredentialMountFactsV2{
		filesystemType: int64(raw.Type),
		flags:          uint64(raw.Flags) & uint64(systemdCredentialMountSecurityFlags),
		fsid:           raw.Fsid.Val,
	}
}

func classifySystemdCredentialObservationV2(
	observation systemdCredentialObservationV2,
	peerUID uint32,
	directory bool,
	maximum int,
) systemdCredentialMaterializationProfileV2 {
	if peerUID == 0 ||
		peerUID == systemdCredentialACLUndefinedID ||
		observation.defaultACL.present ||
		(!observation.defaultACL.present && len(observation.defaultACL.encoded) != 0) ||
		(!observation.accessACL.present && len(observation.accessACL.encoded) != 0) {
		return systemdCredentialMaterializationInvalidV2
	}

	expectedRootMode := uint16(systemdCredentialFileRootACLMode)
	expectedOwnerMode := uint16(systemdCredentialFileOwnerMode)
	expectedACLPermissions := systemdCredentialACLRead
	if directory {
		expectedRootMode = uint16(systemdCredentialDirectoryRootACLMode)
		expectedOwnerMode = uint16(systemdCredentialDirectoryOwnerMode)
		expectedACLPermissions |= systemdCredentialACLExecute
	} else if observation.object.nlink != 1 ||
		maximum <= 0 ||
		observation.object.size == 0 ||
		observation.object.size > uint64(maximum) {
		return systemdCredentialMaterializationInvalidV2
	}

	if observation.object.mode == expectedRootMode &&
		observation.object.uid == 0 &&
		observation.object.gid == 0 &&
		observation.accessACL.present &&
		validateSystemdCredentialACL(
			observation.accessACL.encoded,
			peerUID,
			expectedACLPermissions,
		) {
		return systemdCredentialMaterializationRootACLV2
	}

	if observation.object.mode == expectedOwnerMode &&
		observation.object.uid == peerUID &&
		!observation.accessACL.present &&
		observation.mount.flags&unix.ST_RDONLY != 0 {
		return systemdCredentialMaterializationPeerOwnedReadOnlyV2
	}
	return systemdCredentialMaterializationInvalidV2
}

func sameSystemdCredentialObjectFactsV2(
	left systemdCredentialObjectFactsV2,
	right systemdCredentialObjectFactsV2,
) bool {
	return left == right
}

func sameSystemdCredentialObservationV2(
	left systemdCredentialObservationV2,
	right systemdCredentialObservationV2,
) bool {
	return sameSystemdCredentialObjectFactsV2(left.object, right.object) &&
		left.mount == right.mount &&
		left.accessACL.present == right.accessACL.present &&
		bytes.Equal(left.accessACL.encoded, right.accessACL.encoded) &&
		left.defaultACL.present == right.defaultACL.present &&
		bytes.Equal(left.defaultACL.encoded, right.defaultACL.encoded)
}

func exactSystemdCredentialNamesV2(names []string) bool {
	if len(names) != len(systemdCredentialSpecsV2) {
		return false
	}
	for index, specification := range systemdCredentialSpecsV2 {
		if names[index] != specification.name {
			return false
		}
	}
	return true
}

func sameSystemdCredentialNamesV2(left []string, right []string) bool {
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

func canonicalSystemdCredentialDirectoryV2(directory string) bool {
	if len(directory) < 2 ||
		directory[0] != '/' ||
		directory[len(directory)-1] == '/' ||
		strings.ContainsRune(directory, 0) ||
		strings.Contains(directory, "//") {
		return false
	}
	for _, component := range strings.Split(directory[1:], "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func credentialContextDoneV2(ctx context.Context) bool {
	if ctx == nil {
		return true
	}
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
