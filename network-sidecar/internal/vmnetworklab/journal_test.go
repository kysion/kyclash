package vmnetworklab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func testRecord() JournalRecord {
	record := NewJournalRecord()
	record.RouteLeaseID = "vmnet.0123456789abcdef0123456789abcdef"
	record.SidecarInstanceID = "instance.vm.network"
	record.TunnelGeneration = "tun.request.prepare.1"
	record.TunnelInterface = "utun17"
	record.MihomoChild = ProcessIdentity{
		PID: 4242, StartTime: "Thu Jul 23 10:00:00 2026", Dev: 11, Inode: 12,
		SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	record.State = StateApplied
	return record
}

func TestJournalAtomicRoundTripAndFinalRemoval(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store := NewJournalStore(filepath.Join(directory, "route-lease-v1.json"), false)
	record := testRecord()
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := store.Load()
	if err != nil || !exists || loaded != record {
		t.Fatalf("load = %#v, %v, %v", loaded, exists, err)
	}
	info, err := os.Lstat(store.Path())
	if err != nil || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("unsafe journal mode: %v %v", info, err)
	}
	record.State = StateTeardown
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	record.State = StateReleased
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := store.Load(); err != nil || exists {
		t.Fatalf("journal remained after release: exists=%v err=%v", exists, err)
	}
}

func TestJournalRejectsUnknownFieldsSymlinksAndIncompleteOwnership(t *testing.T) {
	record := testRecord()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)-1] = ','
	encoded = append(encoded, []byte(`"unknown":true}`)...)
	if _, err := DecodeJournalBytes(encoded); err == nil {
		t.Fatal("unknown journal field accepted")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "route-lease-v1.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	store := NewJournalStore(path, false)
	if _, _, err := store.Load(); err == nil {
		t.Fatal("symlinked journal accepted")
	}
	if err := store.Remove(); err == nil {
		t.Fatal("symlinked journal removed")
	}

	record.TunnelInterface = ""
	if err := record.Validate(); err == nil {
		t.Fatal("applied record without exact utun accepted")
	}
}
