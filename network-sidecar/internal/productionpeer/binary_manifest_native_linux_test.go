//go:build linux

package productionpeer

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	binaryIdentityNativeMarkerEnvironmentV1    = "KYCLASH_BINARY_MANIFEST_V1_NATIVE"
	binaryIdentityNativeProfileEnvironmentV1   = "KYCLASH_BINARY_MANIFEST_V1_NATIVE_PROFILE"
	binaryIdentityNativePeerUIDEnvironmentV1   = "KYCLASH_BINARY_MANIFEST_V1_NATIVE_PEER_UID"
	binaryIdentityNativeBrokerUIDEnvironmentV1 = "KYCLASH_BINARY_MANIFEST_V1_NATIVE_BROKER_UID"
	binaryIdentityNativeIPCGIDEnvironmentV1    = "KYCLASH_BINARY_MANIFEST_V1_NATIVE_IPC_GID"
	binaryIdentityNativeRoleEnvironmentV1      = "KYCLASH_BINARY_MANIFEST_V1_NATIVE_ROLE"

	binaryIdentityNativeReplacementPathV1 = "/usr/libexec/.kyclash-network-peer-replacement-v1"
)

type binaryIdentityNativeIDsV1 struct {
	peerUID   uint32
	brokerUID uint32
	ipcGID    uint32
}

type binaryIdentityNativeReplacementOpsV1 struct {
	linuxBinaryIdentityFilesystemOpsV1
	targetDescriptor int
	triggered        bool
	injectionErr     error
}

func (operations *binaryIdentityNativeReplacementOpsV1) openat2(
	directoryDescriptor int,
	path string,
	how *unix.OpenHow,
) (int, error) {
	descriptor, err := operations.linuxBinaryIdentityFilesystemOpsV1.openat2(
		directoryDescriptor,
		path,
		how,
	)
	if err == nil &&
		operations.targetDescriptor < 0 &&
		path == binaryIdentityPeerFileNameV1 &&
		how != nil &&
		how.Flags == uint64(binaryIdentityFileDataFlagsV1()) {
		operations.targetDescriptor = descriptor
	}
	return descriptor, err
}

func (operations *binaryIdentityNativeReplacementOpsV1) pread(
	descriptor int,
	destination []byte,
	offset int64,
) (int, error) {
	count, err := operations.linuxBinaryIdentityFilesystemOpsV1.pread(
		descriptor,
		destination,
		offset,
	)
	if err == nil &&
		count > 0 &&
		!operations.triggered &&
		operations.injectionErr == nil &&
		descriptor == operations.targetDescriptor {
		operations.injectionErr = unix.Renameat2(
			unix.AT_FDCWD,
			binaryIdentityNativeReplacementPathV1,
			unix.AT_FDCWD,
			binaryIdentityPeerPathV1,
			unix.RENAME_EXCHANGE,
		)
		if operations.injectionErr == nil {
			operations.triggered = true
		}
	}
	return count, err
}

func TestNativeFixedBinaryIdentityFilesystemV1(t *testing.T) {
	if os.Getenv(binaryIdentityNativeMarkerEnvironmentV1) == "" {
		t.Skip("native binary identity filesystem gate is not selected")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("native binary identity filesystem gate requires Linux")
	}

	identities := binaryIdentityNativeIDsForTest(t)
	switch profile := os.Getenv(binaryIdentityNativeProfileEnvironmentV1); profile {
	case "accept-unwritable":
		requireNativeBinaryIdentityForTest(t, identities)
		manifest, err := validateFixedBinaryIdentityFilesystemV1()
		if err != nil {
			t.Fatalf("fixed native binary identity filesystem was rejected: %v", err)
		}
		if manifest.peerUID != identities.peerUID ||
			manifest.brokerUID != identities.brokerUID ||
			manifest.ipcGID != identities.ipcGID ||
			manifest.manifestSHA256 == ([32]byte{}) ||
			manifest.peerSHA256 == ([32]byte{}) ||
			manifest.brokerSHA256 == ([32]byte{}) ||
			manifest.hostBootstrapSHA256 == ([32]byte{}) {
			t.Fatal("fixed native binary identity filesystem returned unexpected facts")
		}
		requireNativeBinaryIdentityUnwritableForTest(t)
	case "reject":
		requireNativeRootForTest(t)
		manifest, err := validateFixedBinaryIdentityFilesystemV1()
		requireNativeBinaryIdentityUnavailableForTest(
			t,
			manifest,
			err,
		)
	case "replacement-race":
		requireNativeRootForTest(t)
		operations := &binaryIdentityNativeReplacementOpsV1{
			targetDescriptor: -1,
		}
		manifest, err := validateFixedBinaryIdentityFilesystemV1WithOps(operations)
		requireNativeBinaryIdentityUnavailableForTest(
			t,
			manifest,
			err,
		)
		if operations.injectionErr != nil {
			t.Fatalf("native replacement injection failed: %v", operations.injectionErr)
		}
		if !operations.triggered {
			t.Fatal("native replacement injection did not execute")
		}
	default:
		t.Fatalf("unsupported native binary identity profile: %q", profile)
	}
}

func binaryIdentityNativeIDsForTest(t *testing.T) binaryIdentityNativeIDsV1 {
	t.Helper()
	return binaryIdentityNativeIDsV1{
		peerUID: binaryIdentityNativeIDForTest(
			t,
			binaryIdentityNativePeerUIDEnvironmentV1,
		),
		brokerUID: binaryIdentityNativeIDForTest(
			t,
			binaryIdentityNativeBrokerUIDEnvironmentV1,
		),
		ipcGID: binaryIdentityNativeIDForTest(
			t,
			binaryIdentityNativeIPCGIDEnvironmentV1,
		),
	}
}

func binaryIdentityNativeIDForTest(t *testing.T, name string) uint32 {
	t.Helper()
	encoded := os.Getenv(name)
	decoded, err := strconv.ParseUint(encoded, 10, 32)
	if err != nil || !validBinaryIdentityIDV1(uint32(decoded)) {
		t.Fatalf("native binary identity numeric fact %s is invalid", name)
	}
	return uint32(decoded)
}

func requireNativeRootForTest(t *testing.T) {
	t.Helper()
	realUID, effectiveUID, savedUID := unix.Getresuid()
	realGID, effectiveGID, savedGID := unix.Getresgid()
	if realUID != 0 ||
		effectiveUID != 0 ||
		savedUID != 0 ||
		realGID != 0 ||
		effectiveGID != 0 ||
		savedGID != 0 {
		t.Fatal("native negative profile requires the isolated chroot root identity")
	}
}

func requireNativeBinaryIdentityForTest(
	t *testing.T,
	identities binaryIdentityNativeIDsV1,
) {
	t.Helper()
	var expectedUID uint32
	switch role := os.Getenv(binaryIdentityNativeRoleEnvironmentV1); role {
	case "peer":
		expectedUID = identities.peerUID
	case "broker":
		expectedUID = identities.brokerUID
	default:
		t.Fatalf("unsupported native binary identity role: %q", role)
	}

	realUID, effectiveUID, savedUID := unix.Getresuid()
	realGID, effectiveGID, savedGID := unix.Getresgid()
	if expectedUID == 0 ||
		uint32(realUID) != expectedUID ||
		uint32(effectiveUID) != expectedUID ||
		uint32(savedUID) != expectedUID ||
		uint32(realGID) != identities.ipcGID ||
		uint32(effectiveGID) != identities.ipcGID ||
		uint32(savedGID) != identities.ipcGID {
		t.Fatal("native binary identity process facts do not match the selected role")
	}
	groups, err := unix.Getgroups()
	if err != nil ||
		len(groups) != 1 ||
		groups[0] < 0 ||
		uint32(groups[0]) != identities.ipcGID {
		t.Fatal("native binary identity supplementary groups are not the sole IPC group")
	}
}

func requireNativeBinaryIdentityUnwritableForTest(t *testing.T) {
	t.Helper()
	files := [...]string{
		binaryIdentityManifestPathV1,
		binaryIdentityPeerPathV1,
		binaryIdentityBrokerPathV1,
		binaryIdentityBootstrapPathV1,
	}
	for _, path := range files {
		descriptor, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(descriptor)
			t.Fatalf("native service identity opened a fixed file for writing: %s", path)
		}
		requireNativePermissionDeniedForTest(t, path, "write-open", err)

		if err := unix.Rename(path, path+".moved-by-native-test"); err == nil {
			t.Fatalf("native service identity renamed a fixed file: %s", path)
		} else {
			requireNativePermissionDeniedForTest(t, path, "rename", err)
		}
		if err := unix.Unlink(path); err == nil {
			t.Fatalf("native service identity unlinked a fixed file: %s", path)
		} else {
			requireNativePermissionDeniedForTest(t, path, "unlink", err)
		}
	}

	directories := [...]string{
		"/",
		"/usr",
		"/usr/lib",
		binaryIdentityManifestDirectoryV1,
		binaryIdentityExecutableDirectory,
	}
	for _, directory := range directories {
		path := directory + "/.kyclash-binary-manifest-v1-write-probe"
		if directory == "/" {
			path = "/.kyclash-binary-manifest-v1-write-probe"
		}
		descriptor, err := unix.Open(
			path,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC,
			0o600,
		)
		if err == nil {
			_ = unix.Close(descriptor)
			_ = unix.Unlink(path)
			t.Fatalf("native service identity created a file in fixed directory: %s", directory)
		}
		requireNativePermissionDeniedForTest(t, directory, "create", err)
	}
}

func requireNativePermissionDeniedForTest(
	t *testing.T,
	path string,
	operation string,
	err error,
) {
	t.Helper()
	if !errors.Is(err, unix.EACCES) &&
		!errors.Is(err, unix.EPERM) &&
		!errors.Is(err, unix.EROFS) {
		t.Fatalf(
			"native %s on %s failed for an unexpected reason: %v",
			operation,
			path,
			err,
		)
	}
}

func requireNativeBinaryIdentityUnavailableForTest(
	t *testing.T,
	manifest binaryIdentityManifestV1,
	err error,
) {
	t.Helper()
	if !errors.Is(err, errBinaryIdentityManifestUnavailableV1) ||
		manifest != (binaryIdentityManifestV1{}) {
		t.Fatalf("unsafe native binary identity filesystem escaped: err=%v", err)
	}
}
