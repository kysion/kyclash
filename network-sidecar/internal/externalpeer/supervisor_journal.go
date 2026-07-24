package externalpeer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

var (
	ErrInvalidSupervisorJournal = errors.New("invalid external-peer supervisor journal")
	ErrUnsafeSupervisorFile     = errors.New("unsafe external-peer supervisor file")
)

type SupervisorState string

const (
	SupervisorRecoveryOnly    SupervisorState = "recovery-only"
	SupervisorIdleReady       SupervisorState = "idle-ready"
	SupervisorAccepted        SupervisorState = "accepted"
	SupervisorChildStarting   SupervisorState = "child-starting"
	SupervisorRunning         SupervisorState = "running"
	SupervisorCleaning        SupervisorState = "cleaning"
	SupervisorCleanPostflight SupervisorState = "clean-postflight"
)

type ChildIdentity struct {
	PID           int    `json:"pid"`
	StartIdentity string `json:"start_identity"`
	Path          string `json:"path"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
	SHA256        string `json:"sha256"`
	UID           uint32 `json:"uid"`
	SessionID     int    `json:"session_id"`
	RunID         string `json:"run_id"`
}

// AuthorizedKeysOriginal binds the durable journal to the exact
// authorized_keys bytes and filesystem identity observed before KyClash made
// its one-line mutation. Device/inode identify the pre-replacement file; the
// digest and ownership/mode remain usable after an atomic restore necessarily
// creates a new inode.
type AuthorizedKeysOriginal struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   uint64 `json:"size"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

func (original AuthorizedKeysOriginal) Validate() error {
	if original.Device == 0 ||
		original.Inode == 0 ||
		original.Size > 64*1024 ||
		original.UID == 0 ||
		original.Mode != 0o600 ||
		!validSHA256(original.SHA256) {
		return ErrInvalidSupervisorJournal
	}
	return nil
}

type SupervisorJournal struct {
	SchemaVersion           uint8                   `json:"schema_version"`
	State                   SupervisorState         `json:"state"`
	RunID                   string                  `json:"run_id"`
	TicketHash              string                  `json:"ticket_hash"`
	ExpiresAt               int64                   `json:"expires_at"`
	AuthorizedKeyLine       string                  `json:"authorized_key_line"`
	AuthorizedKeyLineSHA256 string                  `json:"authorized_key_line_sha256"`
	AuthorizedKeysOriginal  *AuthorizedKeysOriginal `json:"authorized_keys_original"`
	Child                   *ChildIdentity          `json:"child"`
}

func (journal SupervisorJournal) Validate() error {
	switch journal.State {
	case SupervisorRecoveryOnly, SupervisorAccepted, SupervisorChildStarting,
		SupervisorRunning, SupervisorCleaning:
	default:
		return ErrInvalidSupervisorJournal
	}
	if journal.SchemaVersion != SchemaVersion ||
		!validRunID(journal.RunID) ||
		!validSHA256(journal.TicketHash) ||
		journal.ExpiresAt <= 0 ||
		!ValidAuthorizedKeyLine(journal.AuthorizedKeyLine) ||
		HashHex([]byte(journal.AuthorizedKeyLine)) != journal.AuthorizedKeyLineSHA256 ||
		!validSHA256(journal.AuthorizedKeyLineSHA256) {
		return ErrInvalidSupervisorJournal
	}
	if journal.Child != nil {
		if err := journal.Child.Validate(journal.RunID); err != nil {
			return err
		}
	}
	if journal.AuthorizedKeysOriginal == nil ||
		journal.AuthorizedKeysOriginal.Validate() != nil {
		return ErrInvalidSupervisorJournal
	}
	if journal.State == SupervisorRunning && journal.Child == nil {
		return ErrInvalidSupervisorJournal
	}
	return nil
}

func (identity ChildIdentity) Validate(runID string) error {
	if identity.PID <= 1 ||
		identity.StartIdentity == "" ||
		len(identity.StartIdentity) > 128 ||
		identity.Path != PeerChildPath ||
		identity.Device == 0 ||
		identity.Inode == 0 ||
		!validSHA256(identity.SHA256) ||
		identity.UID == 0 ||
		identity.SessionID <= 0 ||
		identity.RunID != runID {
		return ErrInvalidSupervisorJournal
	}
	return nil
}

type SupervisorJournalStore struct {
	path        string
	requireRoot bool
}

func NewSupervisorJournalStore(path string, requireRoot bool) SupervisorJournalStore {
	return SupervisorJournalStore{path: path, requireRoot: requireRoot}
}

func (store SupervisorJournalStore) Path() string { return store.path }

func (store SupervisorJournalStore) Load() (SupervisorJournal, bool, error) {
	parent, err := store.validateParent()
	if err != nil {
		return SupervisorJournal{}, false, err
	}
	_ = parent
	info, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return SupervisorJournal{}, false, nil
	}
	if err != nil || !store.safeFile(info, 0o600) {
		return SupervisorJournal{}, false, ErrUnsafeSupervisorFile
	}
	file, err := os.OpenFile(store.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return SupervisorJournal{}, false, ErrUnsafeSupervisorFile
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return SupervisorJournal{}, false, ErrUnsafeSupervisorFile
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxDescriptorSize+1))
	if err != nil || len(data) > MaxDescriptorSize {
		clear(data)
		return SupervisorJournal{}, false, ErrInvalidSupervisorJournal
	}
	after, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(store.path)
	if statErr != nil || pathErr != nil ||
		!os.SameFile(opened, after) ||
		!os.SameFile(opened, pathInfo) ||
		opened.Size() != after.Size() ||
		after.Size() != int64(len(data)) {
		clear(data)
		return SupervisorJournal{}, false, ErrUnsafeSupervisorFile
	}
	journal, err := DecodeSupervisorJournal(data)
	clear(data)
	if err != nil {
		return SupervisorJournal{}, false, err
	}
	return journal, true, nil
}

func (store SupervisorJournalStore) Save(journal SupervisorJournal) error {
	if err := journal.Validate(); err != nil {
		return err
	}
	parent, err := store.validateParent()
	if err != nil {
		return err
	}
	data, err := json.Marshal(journal)
	if err != nil || len(data) > MaxDescriptorSize {
		return ErrInvalidSupervisorJournal
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(parent, ".peer-journal-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	clear(data)
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	info, err := temporary.Stat()
	if err != nil || !store.safeFile(info, 0o600) {
		_ = temporary.Close()
		return ErrUnsafeSupervisorFile
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return err
	}
	return syncParent(parent)
}

func (store SupervisorJournalStore) Remove() error {
	if _, err := store.validateParent(); err != nil {
		return err
	}
	info, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !store.safeFile(info, 0o600) {
		return ErrUnsafeSupervisorFile
	}
	if err := os.Remove(store.path); err != nil {
		return err
	}
	return syncParent(filepath.Dir(store.path))
}

func DecodeSupervisorJournal(data []byte) (SupervisorJournal, error) {
	if err := rejectDuplicateObjectKeys(data); err != nil {
		return SupervisorJournal{}, ErrInvalidSupervisorJournal
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var journal SupervisorJournal
	if err := decoder.Decode(&journal); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		journal.Validate() != nil {
		return SupervisorJournal{}, ErrInvalidSupervisorJournal
	}
	return journal, nil
}

func (store SupervisorJournalStore) validateParent() (string, error) {
	if store.path == "" || !filepath.IsAbs(store.path) {
		return "", ErrUnsafeSupervisorFile
	}
	parent := filepath.Dir(store.path)
	info, err := os.Lstat(parent)
	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 ||
		!store.ownerMatches(info) {
		return "", ErrUnsafeSupervisorFile
	}
	return parent, nil
}

func (store SupervisorJournalStore) safeFile(info os.FileInfo, mode os.FileMode) bool {
	if info == nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != mode.Perm() ||
		!store.ownerMatches(info) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Nlink == 1
}

func (store SupervisorJournalStore) ownerMatches(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	expected := uint32(os.Getuid())
	if store.requireRoot {
		expected = 0
	}
	return stat.Uid == expected
}

func syncParent(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func childIdentityFromFile(
	pid int,
	startIdentity string,
	path string,
	info os.FileInfo,
	hash string,
	uid uint32,
	sessionID int,
	runID string,
) (ChildIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ChildIdentity{}, ErrInvalidSupervisorJournal
	}
	identity := ChildIdentity{
		PID:           pid,
		StartIdentity: startIdentity,
		Path:          path,
		Device:        uint64(stat.Dev),
		Inode:         uint64(stat.Ino),
		SHA256:        hash,
		UID:           uid,
		SessionID:     sessionID,
		RunID:         runID,
	}
	if err := identity.Validate(runID); err != nil {
		return ChildIdentity{}, err
	}
	return identity, nil
}

func (identity ChildIdentity) String() string {
	return "ChildIdentity{pid:" + strconv.Itoa(identity.PID) + ",path:<fixed>,hash:<redacted>}"
}
