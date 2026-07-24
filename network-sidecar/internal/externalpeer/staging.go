package externalpeer

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

var ErrInvalidStagingManifest = errors.New("invalid external-peer staging manifest")

type StagedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	UID    uint32 `json:"uid"`
	Mode   uint32 `json:"mode"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   uint64 `json:"size"`
}

type PeerStagingManifest struct {
	SchemaVersion               uint8      `json:"schema_version"`
	PeerSupervisor              StagedFile `json:"peer_supervisor"`
	PeerChild                   StagedFile `json:"peer_child"`
	PeerConfig                  StagedFile `json:"peer_config"`
	RunTicketExpectation        StagedFile `json:"run_ticket_expectation"`
	PeerListenerBaseline        StagedFile `json:"peer_listener_baseline"`
	ListenerAuditor             StagedFile `json:"listener_auditor"`
	ForcedCommandHelper         StagedFile `json:"forced_command_helper"`
	CourierPublicKeyBase64      string     `json:"courier_public_key_base64"`
	CourierPublicKeyFingerprint string     `json:"courier_public_key_fingerprint"`
}

func DecodePeerStagingManifest(data []byte) (PeerStagingManifest, error) {
	if len(data) == 0 || len(data) > MaxDescriptorSize ||
		rejectDuplicateObjectKeys(data) != nil {
		return PeerStagingManifest{}, ErrInvalidStagingManifest
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest PeerStagingManifest
	if err := decoder.Decode(&manifest); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		manifest.Validate() != nil {
		return PeerStagingManifest{}, ErrInvalidStagingManifest
	}
	return manifest, nil
}

func EncodePeerStagingManifest(
	manifest PeerStagingManifest,
) ([]byte, error) {
	if manifest.Validate() != nil {
		return nil, ErrInvalidStagingManifest
	}
	encoded, err := json.Marshal(manifest)
	if err != nil || len(encoded)+1 > MaxDescriptorSize {
		return nil, ErrInvalidStagingManifest
	}
	return append(encoded, '\n'), nil
}

func (manifest PeerStagingManifest) Validate() error {
	expected := []struct {
		value StagedFile
		path  string
		mode  uint32
	}{
		{manifest.PeerSupervisor, PeerSupervisorPath, 0o755},
		{manifest.PeerChild, PeerChildPath, 0o755},
		{manifest.PeerConfig, PeerFixedConfigPath, 0o600},
		{manifest.RunTicketExpectation, PeerRunTicketExpectationPath, 0o600},
		{manifest.PeerListenerBaseline, PeerListenerBaselinePath, 0o600},
		{manifest.ListenerAuditor, ListenerAuditorPath, 0o755},
		{manifest.ForcedCommandHelper, ForcedCommandHelperPath, 0o755},
	}
	if manifest.SchemaVersion != SchemaVersion {
		return ErrInvalidStagingManifest
	}
	for _, item := range expected {
		if item.value.Path != item.path ||
			item.value.UID != 0 ||
			item.value.Mode != item.mode ||
			item.value.Device == 0 ||
			item.value.Inode == 0 ||
			item.value.Size == 0 ||
			!validSHA256(item.value.SHA256) {
			return ErrInvalidStagingManifest
		}
	}
	publicKey, err := base64.StdEncoding.Strict().DecodeString(manifest.CourierPublicKeyBase64)
	defer clear(publicKey)
	if err != nil ||
		len(publicKey) != 32 ||
		manifest.CourierPublicKeyFingerprint != HashHex(publicKey) {
		return ErrInvalidStagingManifest
	}
	return nil
}

func LoadAndValidatePeerStagingManifest() (PeerStagingManifest, error) {
	info, err := os.Lstat(PeerStagingManifestPath)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 {
		return PeerStagingManifest{}, ErrInvalidStagingManifest
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return PeerStagingManifest{}, ErrInvalidStagingManifest
	}
	file, err := os.OpenFile(PeerStagingManifestPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return PeerStagingManifest{}, ErrInvalidStagingManifest
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return PeerStagingManifest{}, ErrInvalidStagingManifest
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxDescriptorSize+1))
	if err != nil || len(data) > MaxDescriptorSize {
		clear(data)
		return PeerStagingManifest{}, ErrInvalidStagingManifest
	}
	after, afterErr := file.Stat()
	pathInfo, pathErr := os.Lstat(PeerStagingManifestPath)
	if afterErr != nil ||
		pathErr != nil ||
		!os.SameFile(opened, after) ||
		!os.SameFile(opened, pathInfo) ||
		after.Size() != int64(len(data)) {
		clear(data)
		return PeerStagingManifest{}, ErrInvalidStagingManifest
	}
	manifest, err := DecodePeerStagingManifest(data)
	clear(data)
	if err != nil {
		return PeerStagingManifest{}, err
	}
	for _, staged := range []StagedFile{
		manifest.PeerSupervisor,
		manifest.PeerChild,
		manifest.PeerConfig,
		manifest.RunTicketExpectation,
		manifest.PeerListenerBaseline,
		manifest.ListenerAuditor,
		manifest.ForcedCommandHelper,
	} {
		if err := validateStagedFile(staged); err != nil {
			return PeerStagingManifest{}, err
		}
	}
	return manifest, nil
}

func LoadPeerSupervisorConfig(
	manifest PeerStagingManifest,
) (PeerSupervisorConfig, error) {
	if manifest.Validate() != nil ||
		manifest.PeerConfig.Path != PeerFixedConfigPath {
		return PeerSupervisorConfig{}, ErrInvalidStagingManifest
	}
	data, err := readPinnedRootFile(manifest.PeerConfig, MaxDescriptorSize)
	if err != nil {
		return PeerSupervisorConfig{}, err
	}
	defer clear(data)
	config, err := DecodePeerSupervisorConfig(data)
	if err != nil {
		return PeerSupervisorConfig{}, err
	}
	return config, nil
}

func LoadRunTicketExpectation(
	manifest PeerStagingManifest,
) (RunTicketExpectation, error) {
	if manifest.Validate() != nil ||
		manifest.RunTicketExpectation.Path != PeerRunTicketExpectationPath {
		return RunTicketExpectation{}, ErrInvalidStagingManifest
	}
	data, err := readPinnedRootFile(
		manifest.RunTicketExpectation,
		MaxDescriptorSize,
	)
	if err != nil {
		return RunTicketExpectation{}, err
	}
	defer clear(data)
	return DecodeRunTicketExpectation(data)
}

func LoadPeerListenerBaseline(
	manifest PeerStagingManifest,
	config PeerSupervisorConfig,
) (PeerListenerBaseline, error) {
	if manifest.Validate() != nil ||
		config.Validate() != nil ||
		manifest.PeerListenerBaseline.Path != PeerListenerBaselinePath {
		return PeerListenerBaseline{}, ErrInvalidStagingManifest
	}
	data, err := readPinnedRootFile(
		manifest.PeerListenerBaseline,
		MaxChildControlFrame,
	)
	if err != nil {
		return PeerListenerBaseline{}, err
	}
	defer clear(data)
	baseline, err := DecodePeerListenerBaseline(data)
	if err != nil || baseline.ValidateForConfig(config) != nil {
		return PeerListenerBaseline{}, ErrInvalidStagingManifest
	}
	return baseline, nil
}

func readPinnedRootFile(expected StagedFile, maximum int) ([]byte, error) {
	info, err := os.Lstat(expected.Path)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		uint32(info.Mode().Perm()) != expected.Mode {
		return nil, ErrInvalidStagingManifest
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok ||
		stat.Uid != 0 ||
		stat.Nlink != 1 ||
		uint64(stat.Dev) != expected.Device ||
		uint64(stat.Ino) != expected.Inode ||
		uint64(info.Size()) != expected.Size {
		return nil, ErrInvalidStagingManifest
	}
	file, err := os.OpenFile(expected.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidStagingManifest
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrInvalidStagingManifest
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum+1)))
	if err != nil || len(data) > maximum ||
		HashHex(data) != expected.SHA256 {
		clear(data)
		return nil, ErrInvalidStagingManifest
	}
	after, err := file.Stat()
	pathInfo, pathErr := os.Lstat(expected.Path)
	var pathStat *syscall.Stat_t
	var pathStatOK bool
	if pathErr == nil {
		pathStat, pathStatOK = pathInfo.Sys().(*syscall.Stat_t)
	}
	if err != nil || pathErr != nil ||
		!os.SameFile(opened, after) ||
		!os.SameFile(opened, pathInfo) ||
		after.Size() != int64(len(data)) ||
		uint64(after.Size()) != expected.Size ||
		!pathStatOK ||
		uint64(pathStat.Dev) != expected.Device ||
		uint64(pathStat.Ino) != expected.Inode {
		clear(data)
		return nil, ErrInvalidStagingManifest
	}
	return data, nil
}

func validateStagedFile(expected StagedFile) error {
	if expected.Path == "" ||
		!filepath.IsAbs(expected.Path) ||
		filepath.Clean(expected.Path) != expected.Path {
		return ErrInvalidStagingManifest
	}
	info, err := os.Lstat(expected.Path)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		uint32(info.Mode().Perm()) != expected.Mode {
		return ErrInvalidStagingManifest
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok ||
		stat.Uid != expected.UID ||
		stat.Nlink != 1 ||
		uint64(stat.Dev) != expected.Device ||
		uint64(stat.Ino) != expected.Inode ||
		uint64(info.Size()) != expected.Size {
		return ErrInvalidStagingManifest
	}
	file, err := os.OpenFile(
		expected.Path,
		os.O_RDONLY|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return ErrInvalidStagingManifest
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return ErrInvalidStagingManifest
	}
	hasher := sha256.New()
	written, err := io.Copy(
		hasher,
		io.LimitReader(file, 1024*1024*1024+1),
	)
	if err != nil ||
		written > 1024*1024*1024 ||
		hex.EncodeToString(hasher.Sum(nil)) != expected.SHA256 {
		return ErrInvalidStagingManifest
	}
	after, afterErr := file.Stat()
	pathInfo, pathErr := os.Lstat(expected.Path)
	var pathStat *syscall.Stat_t
	var pathStatOK bool
	if pathErr == nil {
		pathStat, pathStatOK = pathInfo.Sys().(*syscall.Stat_t)
	}
	if afterErr != nil ||
		pathErr != nil ||
		!os.SameFile(opened, after) ||
		!os.SameFile(opened, pathInfo) ||
		after.Size() != written ||
		uint64(after.Size()) != expected.Size ||
		!pathStatOK ||
		uint64(pathStat.Dev) != expected.Device ||
		uint64(pathStat.Ino) != expected.Inode {
		return ErrInvalidStagingManifest
	}
	if expected.Mode&0o111 != 0 {
		if runtime.GOOS != "darwin" {
			return ErrInvalidStagingManifest
		}
		binary, err := macho.Open(expected.Path)
		if err != nil {
			return ErrInvalidStagingManifest
		}
		cpu := binary.Cpu
		_ = binary.Close()
		if cpu != macho.CpuArm64 {
			return ErrInvalidStagingManifest
		}
	}
	return nil
}

func (file StagedFile) String() string {
	return "StagedFile{path:" + file.Path + ",uid:" + strconv.Itoa(int(file.UID)) + ",hash:<redacted>}"
}
