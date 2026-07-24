package vmnetworklab

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const journalVersion = 1

type JournalState string

const (
	StateStartPending  JournalState = "start_pending"
	StateAddPending    JournalState = "add_pending"
	StateApplied       JournalState = "applied"
	StateDeletePending JournalState = "delete_pending"
	StateTeardown      JournalState = "teardown_pending"
	StateReleased      JournalState = "released"
	StateRecoveryOnly  JournalState = "recovery_only"
)

// ProcessIdentity is the minimum exact Mihomo identity retained across a
// harness restart. PID alone is never sufficient: the start-time and
// executable filesystem identity must still match before a process may be
// stopped or adopted.
type ProcessIdentity struct {
	PID       int    `json:"pid"`
	StartTime string `json:"start_time"`
	Dev       uint64 `json:"dev"`
	Inode     uint64 `json:"inode"`
	SHA256    string `json:"sha256"`
}

type JournalRecord struct {
	SchemaVersion     int             `json:"schema_version"`
	RouteLeaseID      string          `json:"route_lease_id"`
	SidecarInstanceID string          `json:"sidecar_instance_id"`
	TunnelGeneration  string          `json:"tunnel_generation"`
	TunnelInterface   string          `json:"tunnel_interface"`
	PrivateCIDR       string          `json:"private_cidr"`
	MihomoChild       ProcessIdentity `json:"mihomo_child"`
	State             JournalState    `json:"state"`
}

func NewJournalRecord() JournalRecord {
	return JournalRecord{
		SchemaVersion: journalVersion,
		RouteLeaseID:  newLeaseID(),
		PrivateCIDR:   PrivateCIDR,
		State:         StateStartPending,
	}
}

func newLeaseID() string {
	bytesValue := make([]byte, 16)
	if _, err := rand.Read(bytesValue); err != nil {
		// Failure is not secret material; a deterministic invalid marker makes
		// the subsequent validation fail closed rather than reusing a lease.
		return "invalid-lease"
	}
	return "vmnet." + hex.EncodeToString(bytesValue)
}

func (record JournalRecord) Validate() error {
	if record.SchemaVersion != journalVersion || !validIdentifier(record.RouteLeaseID) || record.PrivateCIDR != PrivateCIDR {
		return errors.New("invalid VM network journal identity")
	}
	if record.SidecarInstanceID != "" && !validIdentifier(record.SidecarInstanceID) {
		return errors.New("invalid VM network sidecar identity")
	}
	if record.TunnelGeneration != "" && !validIdentifier(record.TunnelGeneration) {
		return errors.New("invalid VM network tunnel generation")
	}
	if record.TunnelInterface != "" && !validUTUN(record.TunnelInterface) {
		return errors.New("invalid VM network tunnel interface")
	}
	switch record.State {
	case StateStartPending:
	case StateAddPending, StateApplied, StateDeletePending, StateTeardown:
		if record.SidecarInstanceID == "" || record.TunnelGeneration == "" || !validUTUN(record.TunnelInterface) {
			return errors.New("incomplete VM network journal ownership")
		}
	case StateReleased:
		allTunnelFactsEmpty := record.SidecarInstanceID == "" && record.TunnelGeneration == "" && record.TunnelInterface == ""
		allTunnelFactsPresent := record.SidecarInstanceID != "" && record.TunnelGeneration != "" && validUTUN(record.TunnelInterface)
		if !allTunnelFactsEmpty && !allTunnelFactsPresent {
			return errors.New("incomplete released VM network ownership")
		}
	case StateRecoveryOnly:
		// Recovery-only records intentionally retain the exact facts even when
		// the last operation was ambiguous.  A new App is never accepted.
	default:
		return errors.New("unknown VM network journal state")
	}
	if record.MihomoChild.PID != 0 {
		if record.MihomoChild.PID <= 1 || record.MihomoChild.StartTime == "" || record.MihomoChild.Dev == 0 || record.MihomoChild.Inode == 0 || !validSHA256(record.MihomoChild.SHA256) {
			return errors.New("invalid VM network Mihomo identity")
		}
	}
	return nil
}

func validIdentifier(value string) bool {
	if len(value) < 8 || len(value) > 128 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-", character)) {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// JournalStore is a descriptor-relative, atomic store.  Production use
// requires a root-owned 0700 directory and root-owned 0600 journal; tests may
// opt into a temporary non-root directory while retaining all serialization
// and symlink checks.
type JournalStore struct {
	path        string
	requireRoot bool
}

func NewJournalStore(path string, requireRoot bool) JournalStore {
	return JournalStore{path: path, requireRoot: requireRoot}
}

func (store JournalStore) Path() string { return store.path }

func (store JournalStore) ensureParent() error {
	parent := filepath.Dir(store.path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("journal parent is not a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("journal parent permissions are too broad")
	}
	if store.requireRoot {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("journal parent is not root-owned")
		}
	}
	return nil
}

func (store JournalStore) Load() (JournalRecord, bool, error) {
	if err := store.ensureParent(); err != nil {
		return JournalRecord{}, false, err
	}
	info, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return JournalRecord{}, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return JournalRecord{}, false, errors.New("journal identity is unsafe")
	}
	if store.requireRoot {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return JournalRecord{}, false, errors.New("journal is not root-owned")
		}
	}
	file, err := os.Open(store.path)
	if err != nil {
		return JournalRecord{}, false, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024))
	decoder.DisallowUnknownFields()
	var record JournalRecord
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return JournalRecord{}, false, errors.New("journal is corrupted")
	}
	if err := record.Validate(); err != nil {
		return JournalRecord{}, false, fmt.Errorf("journal is invalid: %w", err)
	}
	return record, true, nil
}

func (store JournalStore) Save(record JournalRecord) error {
	if err := record.Validate(); err != nil {
		return err
	}
	if err := store.ensureParent(); err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(store.path), ".route-lease-v1.*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	// The state directory is root-private in the guest; replacing a file in
	// that directory is atomic and cannot be redirected through a symlink.
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(store.path))
}

func (store JournalStore) Remove() error {
	if err := store.ensureParent(); err != nil {
		return err
	}
	info, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("refusing unsafe journal removal")
	}
	if store.requireRoot {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("refusing non-root journal removal")
		}
	}
	if err := os.Remove(store.path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(store.path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// DecodeJournalBytes is used by contract tests without touching the fixed
// guest filesystem.
func DecodeJournalBytes(encoded []byte) (JournalRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record JournalRecord
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return JournalRecord{}, errors.New("journal is corrupted")
	}
	return record, record.Validate()
}
