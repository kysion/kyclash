//go:build linux || darwin

package productionpeer

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStablePublicConfigReadAcceptsReadOnlyButRejectsWritableOrSymlink(t *testing.T) {
	encoded, err := os.ReadFile("testdata/valid-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, LinuxConfigFileName)
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := readStablePublicConfigAt(
		directory,
		LinuxConfigFileName,
		MaxConfigSize,
		uint32(os.Geteuid()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeConfig(bytes.NewReader(loaded)); err != nil {
		clear(loaded)
		t.Fatalf("stable public config bytes did not decode: %v", err)
	}
	clear(loaded)

	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := readStablePublicConfigAt(
		directory,
		LinuxConfigFileName,
		MaxConfigSize,
		uint32(os.Geteuid()),
	); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("group-writable public config was not refused: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "config-target.json")
	if err := os.WriteFile(target, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readStablePublicConfigAt(
		directory,
		LinuxConfigFileName,
		MaxConfigSize,
		uint32(os.Geteuid()),
	); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("public config symlink was not refused: %v", err)
	}
}

func TestV2PublicConfigLocationAndCredentialNamesAreFixed(t *testing.T) {
	if LinuxConfigDirectory != "/etc/kyclash" ||
		LinuxConfigFileName != "network-peer-v2.json" ||
		LinuxConfigPath != "/etc/kyclash/network-peer-v2.json" ||
		!validCredentialName(TLSCertificateCredentialName) ||
		!validCredentialName(TLSPrivateKeyCredentialName) ||
		!validCredentialName(WireGuardPrivateCredentialName) {
		t.Fatal("fixed config or credential contract drifted")
	}
}
