package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunRejectsMalformedInvocation(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("malformed invocation unexpectedly accepted")
	}
}

func TestReadRegularRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegular(link, 128, true); err == nil {
		t.Fatal("symlink unexpectedly accepted")
	}
}

func TestReadRegularRejectsOversizedAndUnsafePrivateInputs(t *testing.T) {
	directory := t.TempDir()
	oversized := filepath.Join(directory, "oversized")
	if err := os.WriteFile(oversized, make([]byte, 129), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegular(oversized, 128, true); err == nil {
		t.Fatal("oversized fixture unexpectedly accepted")
	}
	unsafe := filepath.Join(directory, "unsafe")
	if err := os.WriteFile(unsafe, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegular(unsafe, 128, true); err == nil {
		t.Fatal("world-readable private fixture unexpectedly accepted")
	}
}
