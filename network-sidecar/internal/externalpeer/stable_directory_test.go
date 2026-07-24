package externalpeer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStableDirectoryCreateReadExactNamesAndRefuseLinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := OpenStableDirectory(root, uint32(os.Getuid()), 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	data := []byte("public")
	if err := directory.CreateExactFile("client-public-v1.json", data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := directory.RequireExactNames([]string{"client-public-v1.json"}); err != nil {
		t.Fatal(err)
	}
	read, err := directory.ReadCreateOnlyFile(
		"client-public-v1.json",
		64,
		0o600,
	)
	if err != nil || string(read) != string(data) {
		t.Fatalf("stable read failed: %q %v", read, err)
	}
	clear(read)
	if err := os.Symlink(
		"client-public-v1.json",
		filepath.Join(root, "tls-client.csr.der"),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.ReadCreateOnlyFile(
		"tls-client.csr.der",
		64,
		0o600,
	); err == nil {
		t.Fatal("symlink artifact was accepted")
	}
	if err := directory.RequireExactNames([]string{
		"client-public-v1.json",
	}); err == nil {
		t.Fatal("extra linked artifact was not detected")
	}
	if err := os.Remove(filepath.Join(root, "tls-client.csr.der")); err != nil {
		t.Fatal(err)
	}
	if err := directory.RemoveExact("client-public-v1.json"); err != nil {
		t.Fatal(err)
	}
	if err := directory.RemoveExact("client-public-v1.json"); err != nil {
		t.Fatal("second removal of an absent run artifact was not idempotent:", err)
	}
	if err := directory.RequireExactNames(nil); err != nil {
		t.Fatal(err)
	}
}

func TestStableDirectoryRefusesWrongModeAndHardLink(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := OpenStableDirectory(root, uint32(os.Getuid()), 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	path := filepath.Join(root, "client-public-v1.json")
	if err := os.WriteFile(path, []byte("public"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.ReadCreateOnlyFile(
		"client-public-v1.json",
		64,
		0o600,
	); err == nil {
		t.Fatal("wrong mode was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(root, "linked.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.ReadCreateOnlyFile(
		"client-public-v1.json",
		64,
		0o600,
	); err == nil {
		t.Fatal("hard-linked artifact was accepted")
	}
}
