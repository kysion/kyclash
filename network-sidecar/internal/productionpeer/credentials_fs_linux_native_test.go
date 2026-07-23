//go:build linux

package productionpeer

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	systemdCredentialNativeProfileEnvironmentV2   = "KYCLASH_CREDENTIAL_V2_NATIVE_PROFILE"
	systemdCredentialNativeDirectoryEnvironmentV2 = "KYCLASH_CREDENTIAL_V2_NATIVE_DIRECTORY"
	systemdCredentialNativePeerUIDEnvironmentV2   = "KYCLASH_CREDENTIAL_V2_NATIVE_PEER_UID"
	systemdCredentialNativeReadyEnvironmentV2     = "KYCLASH_CREDENTIAL_V2_NATIVE_READY_FILE"
	systemdCredentialNativeReleaseEnvironmentV2   = "KYCLASH_CREDENTIAL_V2_NATIVE_RELEASE_FILE"
)

var systemdCredentialNativeContentsV2 = map[string][]byte{
	TLSCertificateCredentialName:   []byte("kyclash-native-v2-synthetic-certificate"),
	TLSPrivateKeyCredentialName:    []byte("kyclash-native-v2-synthetic-tls-private-key"),
	WireGuardPrivateCredentialName: []byte("kyclash-native-v2-synthetic-wireguard-private-key"),
}

func TestNativeSystemdCredentialFilesystemV2Materialization(t *testing.T) {
	profile, enabled := os.LookupEnv(systemdCredentialNativeProfileEnvironmentV2)
	if !enabled {
		t.Skip("native Linux credential materialization gate is opt-in")
	}
	if profile != "root-acl" &&
		profile != "peer-owned-read-only" &&
		profile != "systemd-materialized" {
		t.Fatal("native credential profile is not an allowed test value")
	}
	directoryEnvironment := systemdCredentialNativeDirectoryEnvironmentV2
	if profile == "systemd-materialized" {
		directoryEnvironment = "CREDENTIALS_DIRECTORY"
	}
	directory, directoryPresent := os.LookupEnv(directoryEnvironment)
	peerUIDText, peerUIDPresent := os.LookupEnv(systemdCredentialNativePeerUIDEnvironmentV2)
	peerUID64, parseErr := strconv.ParseUint(peerUIDText, 10, 32)
	if !directoryPresent ||
		!peerUIDPresent ||
		parseErr != nil ||
		peerUID64 == 0 ||
		uint64(os.Geteuid()) != peerUID64 {
		t.Fatal("native credential test identity is invalid")
	}
	recordNativeCredentialMaterializationFactsV2(t, directory, uint32(peerUID64))

	loaded, err := readSystemdCredentialFilesystemV2(
		t.Context(),
		directory,
		uint32(peerUID64),
	)
	if err != nil || loaded == nil {
		t.Fatalf("locked native credential materialization was rejected: %v", err)
	}
	aliases := [][]byte{
		loaded.tlsCertificatePEM[:cap(loaded.tlsCertificatePEM)],
		loaded.tlsPrivateKeyPEM[:cap(loaded.tlsPrivateKeyPEM)],
		loaded.wireGuardPrivateKey[:cap(loaded.wireGuardPrivateKey)],
	}
	for name, actual := range map[string][]byte{
		TLSCertificateCredentialName:   loaded.tlsCertificatePEM,
		TLSPrivateKeyCredentialName:    loaded.tlsPrivateKeyPEM,
		WireGuardPrivateCredentialName: loaded.wireGuardPrivateKey,
	} {
		if !bytes.Equal(actual, systemdCredentialNativeContentsV2[name]) {
			loaded.Close()
			t.Fatal("native credential bytes did not match the synthetic fixture")
		}
	}
	loaded.Close()
	if !allZeroSystemdCredentialBuffersForTest(aliases) {
		t.Fatal("native credential result retained owned bytes after Close")
	}

	assertNativeCredentialViewCannotMutateV2(t, directory)
	if profile == "systemd-materialized" {
		holdNativeSystemdCredentialMaterializationV2(t)
	}
}

func holdNativeSystemdCredentialMaterializationV2(t *testing.T) {
	t.Helper()
	readyPath, readyPresent := os.LookupEnv(systemdCredentialNativeReadyEnvironmentV2)
	releasePath, releasePresent := os.LookupEnv(systemdCredentialNativeReleaseEnvironmentV2)
	if !readyPresent ||
		!releasePresent ||
		!filepath.IsAbs(readyPath) ||
		!filepath.IsAbs(releasePath) ||
		readyPath == releasePath {
		t.Fatal("native systemd hold paths are invalid")
	}
	ready, err := os.OpenFile(readyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("native systemd readiness marker could not be created")
	}
	if _, err := ready.WriteString("ready\n"); err != nil {
		_ = ready.Close()
		t.Fatal("native systemd readiness marker could not be written")
	}
	if err := ready.Close(); err != nil {
		t.Fatal("native systemd readiness marker could not be closed")
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Lstat(releasePath); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal("native systemd release marker check failed")
		}
		if time.Now().After(deadline) {
			t.Fatal("native systemd materialization hold timed out")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func recordNativeCredentialMaterializationFactsV2(
	t *testing.T,
	directory string,
	peerUID uint32,
) {
	t.Helper()
	descriptor, err := unix.Open(
		directory,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		t.Fatalf("native credential directory facts unavailable: %v", ErrCredentialUnavailable)
	}
	defer unix.Close(descriptor)
	observation, err := observeSystemdCredentialDescriptorV2(
		linuxSystemdCredentialFilesystemOpsV2{},
		descriptor,
	)
	if err != nil {
		t.Fatalf("native credential directory observation failed: %v", err)
	}
	defer observation.clear()
	materialization := classifySystemdCredentialObservationV2(
		observation,
		peerUID,
		true,
		0,
	)
	if materialization == systemdCredentialMaterializationInvalidV2 {
		t.Fatal("native credential directory does not match a locked materialization")
	}
	t.Logf(
		"credential_v2_native_facts profile=%d mode=%#o uid=%d gid=%d mount_id=%d fs_type=%#x mount_flags=%#x access_acl=%t default_acl=%t",
		materialization,
		observation.object.mode,
		observation.object.uid,
		observation.object.gid,
		observation.object.mountID,
		observation.mount.filesystemType,
		observation.mount.flags,
		observation.accessACL.present,
		observation.defaultACL.present,
	)
}

func assertNativeCredentialViewCannotMutateV2(t *testing.T, directory string) {
	t.Helper()
	for _, specification := range systemdCredentialSpecsV2 {
		path := filepath.Join(directory, specification.name)
		descriptor, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err == nil {
			_ = descriptor.Close()
			t.Fatal("Peer identity unexpectedly opened a credential for writing")
		}
		if !errors.Is(err, os.ErrPermission) {
			var pathError *os.PathError
			if !errors.As(err, &pathError) {
				t.Fatal("credential write refusal did not return a path error")
			}
		}
		if err := os.Chmod(path, 0o600); err == nil {
			t.Fatal("Peer identity unexpectedly changed credential mode")
		}
		if err := os.Remove(path); err == nil {
			t.Fatal("Peer identity unexpectedly removed a credential")
		}
	}

	source := filepath.Join(directory, TLSCertificateCredentialName)
	destination := filepath.Join(directory, "renamed-credential")
	if err := os.Rename(source, destination); err == nil {
		_ = os.Rename(destination, source)
		t.Fatal("Peer identity unexpectedly renamed a credential")
	}
	extra := filepath.Join(directory, "unexpected-credential")
	if err := os.WriteFile(extra, []byte("synthetic"), 0o400); err == nil {
		_ = os.Remove(extra)
		t.Fatal("Peer identity unexpectedly created a credential-directory entry")
	}
}
