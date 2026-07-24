package externalpeerhost

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyInitIsCreateOnlyRawAndModeBound(t *testing.T) {
	t.Parallel()
	layout := testLayout(t)
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x42}, 64))
	if err := InitializeKeyStore(layout, entropy); err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Lstat(layout.PrivateRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("unsafe private root: %#v %v", rootInfo, err)
	}
	privatePath := filepath.Join(layout.PrivateRoot, PrivateKeyName)
	publicPath := filepath.Join(layout.PrivateRoot, PublicKeyName)
	privateInfo, err := os.Lstat(privatePath)
	if err != nil ||
		!privateInfo.Mode().IsRegular() ||
		privateInfo.Mode().Perm() != 0o600 ||
		privateInfo.Size() != ed25519.PrivateKeySize {
		t.Fatalf("unsafe private key file: %#v %v", privateInfo, err)
	}
	publicInfo, err := os.Lstat(publicPath)
	if err != nil ||
		!publicInfo.Mode().IsRegular() ||
		publicInfo.Mode().Perm() != 0o600 ||
		publicInfo.Size() != ed25519.PublicKeySize {
		t.Fatalf("unsafe public key file: %#v %v", publicInfo, err)
	}
	if err := InitializeKeyStore(
		layout,
		bytes.NewReader(bytes.Repeat([]byte{0x21}, 64)),
	); err == nil {
		t.Fatal("key-init reused or replaced an existing key")
	}
}

func TestKeyLoadRejectsBadModeSymlinkAndHardLink(t *testing.T) {
	t.Parallel()
	t.Run("bad root mode", func(t *testing.T) {
		layout := testLayout(t)
		if err := InitializeKeyStore(
			layout,
			bytes.NewReader(bytes.Repeat([]byte{0x41}, 64)),
		); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(layout.PrivateRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if keys, err := loadKeyPair(layout); err == nil {
			keys.close()
			t.Fatal("world-readable key parent was accepted")
		}
	})
	t.Run("symlink private key", func(t *testing.T) {
		layout := testLayout(t)
		if err := os.MkdirAll(layout.PrivateRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(layout.PrivateRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "private.bin")
		if err := os.WriteFile(
			target,
			bytes.Repeat([]byte{0x12}, ed25519.PrivateKeySize),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(
			target,
			filepath.Join(layout.PrivateRoot, PrivateKeyName),
		); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(layout.PrivateRoot, PublicKeyName),
			bytes.Repeat([]byte{0x13}, ed25519.PublicKeySize),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if keys, err := loadKeyPair(layout); err == nil {
			keys.close()
			t.Fatal("symlinked private key was accepted")
		}
	})
	t.Run("hard-linked private key", func(t *testing.T) {
		layout := testLayout(t)
		if err := InitializeKeyStore(
			layout,
			bytes.NewReader(bytes.Repeat([]byte{0x31}, 64)),
		); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(
			filepath.Join(layout.PrivateRoot, PrivateKeyName),
			filepath.Join(layout.PrivateRoot, "private-link.bin"),
		); err != nil {
			t.Fatal(err)
		}
		if keys, err := loadKeyPair(layout); err == nil {
			keys.close()
			t.Fatal("hard-linked private key was accepted")
		}
	})
}

func TestStableReadRejectsPathReplacement(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "public.bin")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	directory, err := openSecureDirectory(root, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	_, err = directory.readStableFile("public.bin", 64, func() {
		if renameErr := os.Rename(path, filepath.Join(root, "old.bin")); renameErr != nil {
			t.Fatal(renameErr)
		}
		if writeErr := os.WriteFile(path, []byte("replaced"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	})
	if err == nil {
		t.Fatal("path replacement during stable read was accepted")
	}
}

func testLayout(t *testing.T) Layout {
	t.Helper()
	root, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	moduleRoot := filepath.Join(root, "network-sidecar")
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(moduleRoot, "go.mod"),
		[]byte("module github.com/kysion/kyclash/network-sidecar\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	layout, err := FixedLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	return layout
}
