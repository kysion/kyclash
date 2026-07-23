//go:build linux || darwin

package productionpeer

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStableCredentialReadAcceptsOnlyOwnedRegularPrivateFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, TLSPrivateKeyCredentialName)
	content := []byte("bounded-test-credential")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := readStableCredentialAt(
		directory,
		TLSPrivateKeyCredentialName,
		int64(len(content)),
		uint32(os.Geteuid()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(loaded)
	if !bytes.Equal(loaded, content) {
		t.Fatal("stable credential read changed bytes")
	}

	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableCredentialAt(
		directory,
		TLSPrivateKeyCredentialName,
		int64(len(content)),
		uint32(os.Geteuid()),
	); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("group-readable credential was not refused: %v", err)
	}
}

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

func TestStableCredentialReadRejectsSymlinkUnknownNameNULAndOversize(t *testing.T) {
	newDirectory := func(t *testing.T) string {
		t.Helper()
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		return directory
	}
	expectedUID := uint32(os.Geteuid())

	t.Run("file-symlink", func(t *testing.T) {
		directory := newDirectory(t)
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(directory, TLSCertificateCredentialName)); err != nil {
			t.Fatal(err)
		}
		if _, err := readStableCredentialAt(
			directory,
			TLSCertificateCredentialName,
			64,
			expectedUID,
		); !errors.Is(err, ErrCredentialUnavailable) {
			t.Fatalf("credential symlink was not refused: %v", err)
		}
	})

	t.Run("directory-symlink", func(t *testing.T) {
		directory := newDirectory(t)
		if err := os.WriteFile(
			filepath.Join(directory, TLSCertificateCredentialName),
			[]byte("secret"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		linkRoot := t.TempDir()
		link := filepath.Join(linkRoot, "credentials")
		if err := os.Symlink(directory, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readStableCredentialAt(
			link,
			TLSCertificateCredentialName,
			64,
			expectedUID,
		); !errors.Is(err, ErrCredentialUnavailable) {
			t.Fatalf("credential directory symlink was not refused: %v", err)
		}
	})

	t.Run("unknown-name", func(t *testing.T) {
		if _, err := readStableCredentialAt(
			newDirectory(t),
			"caller-selected-private-key",
			64,
			expectedUID,
		); !errors.Is(err, ErrCredentialUnavailable) {
			t.Fatalf("caller-selected credential name was not refused: %v", err)
		}
	})

	for name, content := range map[string][]byte{
		"nul":      {'a', 0, 'b'},
		"oversize": bytes.Repeat([]byte{'x'}, 65),
	} {
		t.Run(name, func(t *testing.T) {
			directory := newDirectory(t)
			if err := os.WriteFile(
				filepath.Join(directory, WireGuardPrivateCredentialName),
				content,
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			if _, err := readStableCredentialAt(
				directory,
				WireGuardPrivateCredentialName,
				64,
				expectedUID,
			); !errors.Is(err, ErrCredentialUnavailable) {
				t.Fatalf("unsafe credential was not refused: %v", err)
			}
		})
	}
}

func TestCredentialFactsRequireExactOwnerPrivateModeAndBounds(t *testing.T) {
	regularPrivate := uint32(unix.S_IFREG | 0o600)
	if !credentialFactsValid(regularPrivate, 0, 1, 0, 1) {
		t.Fatal("locked root-owned credential facts were rejected")
	}
	for name, valid := range map[string]bool{
		"wrong-owner": credentialFactsValid(regularPrivate, 501, 1, 0, 1),
		"group-mode":  credentialFactsValid(uint32(unix.S_IFREG|0o640), 0, 1, 0, 1),
		"directory":   credentialFactsValid(uint32(unix.S_IFDIR|0o600), 0, 1, 0, 1),
		"empty":       credentialFactsValid(regularPrivate, 0, 0, 0, 1),
		"oversized":   credentialFactsValid(regularPrivate, 0, 2, 0, 1),
	} {
		if valid {
			t.Fatalf("%s credential facts were accepted", name)
		}
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
