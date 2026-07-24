package externalpeergueststaging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func runFixedCommand(
	ctx context.Context,
	executable string,
	arguments ...string,
) ([]byte, error) {
	if ctx == nil ||
		!filepath.IsAbs(executable) ||
		filepath.Clean(executable) != executable {
		return nil, ErrGuestStaging
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"LC_ALL=C",
		"LANG=C",
	}
	output, err := command.CombinedOutput()
	if err != nil || len(output) > sshBootstrapMaxFile {
		clear(output)
		return nil, ErrGuestStaging
	}
	return output, nil
}

func parseDSCLFields(data []byte) (map[string][]string, error) {
	if len(data) == 0 || len(data) > sshBootstrapMaxFile ||
		bytes.Contains(data, []byte{0}) {
		return nil, ErrGuestStaging
	}
	result := make(map[string][]string)
	var active string
	for _, raw := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t') {
			if active == "" {
				return nil, ErrGuestStaging
			}
			result[active] = append(result[active], strings.TrimSpace(raw))
			continue
		}
		name, value, ok := strings.Cut(raw, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, ErrGuestStaging
		}
		active = name
		if _, exists := result[name]; exists {
			return nil, ErrGuestStaging
		}
		value = strings.TrimSpace(value)
		if value == "" {
			result[name] = nil
		} else {
			result[name] = []string{value}
		}
	}
	if len(result) == 0 {
		return nil, ErrGuestStaging
	}
	return result, nil
}

func parseUint32Field(
	fields map[string][]string,
	name string,
) (uint32, error) {
	value := singleField(fields, name)
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, ErrGuestStaging
	}
	return uint32(parsed), nil
}

func singleField(fields map[string][]string, name string) string {
	values := fields[name]
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func parseSSHDFields(data []byte) (map[string]string, error) {
	if len(data) == 0 || len(data) > sshBootstrapMaxFile ||
		bytes.Contains(data, []byte{0}) {
		return nil, ErrGuestStaging
	}
	result := make(map[string]string)
	for _, raw := range strings.Split(string(data), "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 2 {
			continue
		}
		name := strings.ToLower(fields[0])
		value := strings.Join(fields[1:], " ")
		if _, exists := result[name]; exists {
			return nil, ErrGuestStaging
		}
		result[name] = value
	}
	if len(result) == 0 {
		return nil, ErrGuestStaging
	}
	return result, nil
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func requireSafeDirectory(
	path string,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrGuestStaging
	}
	info, err := os.Lstat(path)
	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		(mode != 0 && info.Mode().Perm() != mode.Perm()) ||
		(mode == 0 && info.Mode().Perm()&0o022 != 0) {
		return ErrGuestStaging
	}
	identity, err := identityFromInfo(info)
	if err != nil ||
		identity.UID != uid ||
		identity.GID != gid ||
		identity.Links < 1 {
		return ErrGuestStaging
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return ErrGuestStaging
	}
	return nil
}

func readSafeFile(
	path string,
	uid uint32,
	gid uint32,
	mode os.FileMode,
	maximum int64,
) ([]byte, fileIdentity, error) {
	if !filepath.IsAbs(path) ||
		filepath.Clean(path) != path ||
		maximum <= 0 {
		return nil, fileIdentity{}, ErrGuestStaging
	}
	before, err := os.Lstat(path)
	if err != nil ||
		!safeSystemRegularInfo(before, uid, gid, mode) ||
		before.Size() < 0 ||
		before.Size() > maximum {
		return nil, fileIdentity{}, ErrGuestStaging
	}
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fileIdentity{}, ErrGuestStaging
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, fileIdentity{}, ErrGuestStaging
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fileIdentity{}, ErrGuestStaging
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil ||
		int64(len(data)) != before.Size() ||
		int64(len(data)) > maximum {
		clear(data)
		return nil, fileIdentity{}, ErrGuestStaging
	}
	after, statErr := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if statErr != nil ||
		pathErr != nil ||
		!os.SameFile(before, after) ||
		!os.SameFile(after, pathAfter) ||
		!safeSystemRegularInfo(after, uid, gid, mode) ||
		!safeSystemRegularInfo(pathAfter, uid, gid, mode) {
		clear(data)
		return nil, fileIdentity{}, ErrGuestStaging
	}
	identity, err := identityFromInfo(after)
	if err != nil {
		clear(data)
		return nil, fileIdentity{}, ErrGuestStaging
	}
	identity.SHA256 = hashHex(data)
	return data, identity, nil
}

func safeSystemRegularInfo(
	info os.FileInfo,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) bool {
	if info == nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		(mode != 0 && info.Mode().Perm() != mode.Perm()) ||
		(mode == 0 && info.Mode().Perm()&0o022 != 0) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok &&
		stat.Uid == uid &&
		stat.Gid == gid &&
		stat.Nlink == 1
}

func snapshotOptionalFile(
	path string,
	uid uint32,
	gid uint32,
	mode os.FileMode,
	maximum int64,
	backupName string,
	allowAbsentParent bool,
) (recoveryFile, []byte, error) {
	if !fixedBaseName(backupName) {
		return recoveryFile{}, nil, ErrGuestStaging
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if !allowAbsentParent {
			return recoveryFile{}, nil, ErrGuestStaging
		}
		return recoveryFile{Path: path, Existed: false}, nil, nil
	}
	if err != nil || info == nil {
		return recoveryFile{}, nil, ErrGuestStaging
	}
	data, identity, err := readSafeFile(path, uid, gid, mode, maximum)
	if err != nil {
		return recoveryFile{}, nil, err
	}
	return recoveryFile{
		Path:             path,
		Existed:          true,
		Device:           identity.Device,
		Inode:            identity.Inode,
		UID:              identity.UID,
		GID:              identity.GID,
		Mode:             identity.Mode,
		Links:            identity.Links,
		Size:             identity.Size,
		ModifiedUnixNano: identity.ModifiedUnixNano,
		SHA256:           identity.SHA256,
		BackupName:       backupName,
	}, data, nil
}

func createSystemFileExclusive(
	path string,
	data []byte,
	uid int,
	gid int,
	mode os.FileMode,
) error {
	if !filepath.IsAbs(path) ||
		filepath.Clean(path) != path ||
		!fixedBaseName(filepath.Base(path)) ||
		!pathAbsent(path) {
		return ErrGuestStaging
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil ||
		!parentInfo.IsDir() ||
		parentInfo.Mode()&os.ModeSymlink != 0 ||
		parentInfo.Mode().Perm()&0o022 != 0 {
		return ErrGuestStaging
	}
	parentIdentity, err := identityFromInfo(parentInfo)
	if err != nil ||
		(parentIdentity.UID != uint32(uid) && parentIdentity.UID != 0) {
		return ErrGuestStaging
	}
	fd, err := unix.Open(
		path,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		uint32(mode.Perm()),
	)
	if err != nil {
		return ErrGuestStaging
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return ErrGuestStaging
	}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if file.Chown(uid, gid) != nil || file.Chmod(mode.Perm()) != nil {
		return ErrGuestStaging
	}
	written, err := file.Write(data)
	if err != nil || written != len(data) || file.Sync() != nil {
		return ErrGuestStaging
	}
	info, err := file.Stat()
	if err != nil ||
		!safeSystemRegularInfo(info, uint32(uid), uint32(gid), mode) ||
		info.Size() != int64(len(data)) {
		return ErrGuestStaging
	}
	if err := file.Close(); err != nil {
		return ErrGuestStaging
	}
	failed = false
	installed, err := os.Lstat(path)
	if err != nil ||
		!os.SameFile(info, installed) ||
		!safeSystemRegularInfo(installed, uint32(uid), uint32(gid), mode) {
		return ErrGuestStaging
	}
	return syncDirectory(parent)
}

func createSystemFileAtomic(
	path string,
	data []byte,
	uid int,
	gid int,
	mode os.FileMode,
) error {
	temporary := path + ".pending"
	if !pathAbsent(path) || !pathAbsent(temporary) {
		return ErrGuestStaging
	}
	if err := createSystemFileExclusive(
		temporary, data, uid, gid, mode,
	); err != nil {
		return err
	}
	failed := true
	defer func() {
		if failed {
			_ = os.Remove(temporary)
		}
	}()
	if err := os.Rename(temporary, path); err != nil {
		return ErrGuestStaging
	}
	failed = false
	return syncDirectory(filepath.Dir(path))
}

func removeKnownAtomicTemporary(
	path string,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) error {
	if pathAbsent(path) {
		return nil
	}
	data, identity, err := readSafeFile(
		path, uid, gid, mode, sshBootstrapMaxFile,
	)
	clear(data)
	if err != nil || identity.Device == 0 || identity.Inode == 0 {
		return ErrGuestStaging
	}
	if err := os.Remove(path); err != nil {
		return ErrGuestStaging
	}
	return syncDirectory(filepath.Dir(path))
}

func replaceOwnedFile(
	path string,
	original recoveryFile,
	data []byte,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) error {
	if original.Path != path {
		return ErrGuestStaging
	}
	if original.Existed {
		if err := verifyFileMatchesRecovery(original); err != nil {
			return err
		}
	} else if !pathAbsent(path) {
		return ErrGuestStaging
	}
	temporary := filepath.Join(
		filepath.Dir(path),
		".kyclash-authorized-keys-bootstrap-v1",
	)
	if err := createSystemFileExclusive(
		temporary,
		data,
		int(uid),
		int(gid),
		mode,
	); err != nil {
		return err
	}
	failed := true
	defer func() {
		if failed {
			_ = os.Remove(temporary)
		}
	}()
	if original.Existed {
		if err := verifyFileMatchesRecovery(original); err != nil {
			return err
		}
	} else if !pathAbsent(path) {
		return ErrGuestStaging
	}
	if err := os.Rename(temporary, path); err != nil {
		return ErrGuestStaging
	}
	failed = false
	current, _, err := readSafeFile(path, uid, gid, mode, 64*1024)
	if err != nil || !bytes.Equal(current, data) {
		clear(current)
		return ErrGuestStaging
	}
	clear(current)
	return syncDirectory(filepath.Dir(path))
}

func verifyFileMatchesRecovery(snapshot recoveryFile) error {
	if !snapshot.Existed {
		if pathAbsent(snapshot.Path) {
			return nil
		}
		return ErrGuestStaging
	}
	data, identity, err := readSafeFile(
		snapshot.Path,
		snapshot.UID,
		snapshot.GID,
		os.FileMode(snapshot.Mode),
		sshBootstrapMaxFile,
	)
	defer clear(data)
	if err != nil ||
		identity.Device != snapshot.Device ||
		identity.Inode != snapshot.Inode ||
		identity.UID != snapshot.UID ||
		identity.GID != snapshot.GID ||
		identity.Mode != snapshot.Mode ||
		identity.Links != snapshot.Links ||
		identity.Size != snapshot.Size ||
		identity.ModifiedUnixNano != snapshot.ModifiedUnixNano ||
		identity.SHA256 != snapshot.SHA256 {
		return ErrGuestStaging
	}
	return nil
}

func verifyFileIdentityAtPath(path string, snapshot recoveryFile) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		!snapshot.Existed {
		return ErrGuestStaging
	}
	data, identity, err := readSafeFile(
		path,
		snapshot.UID,
		snapshot.GID,
		os.FileMode(snapshot.Mode),
		sshBootstrapMaxFile,
	)
	defer clear(data)
	if err != nil ||
		identity.Device != snapshot.Device ||
		identity.Inode != snapshot.Inode ||
		identity.UID != snapshot.UID ||
		identity.GID != snapshot.GID ||
		identity.Mode != snapshot.Mode ||
		identity.Links != snapshot.Links ||
		identity.Size != snapshot.Size ||
		identity.ModifiedUnixNano != snapshot.ModifiedUnixNano ||
		identity.SHA256 != snapshot.SHA256 {
		return ErrGuestStaging
	}
	return nil
}

func verifyRecoverySnapshot(
	snapshot recoveryFile,
	backupRoot string,
) error {
	if !snapshot.Existed ||
		!fixedBaseName(snapshot.BackupName) {
		return ErrGuestStaging
	}
	data, _, err := readSafeFile(
		filepath.Join(backupRoot, snapshot.BackupName),
		0,
		0,
		0o600,
		sshBootstrapMaxFile,
	)
	defer clear(data)
	if err != nil ||
		uint64(len(data)) != snapshot.Size ||
		hashHex(data) != snapshot.SHA256 {
		return ErrGuestStaging
	}
	return nil
}

func removeSnapshotExact(snapshot recoveryFile) error {
	if err := verifyFileMatchesRecovery(snapshot); err != nil {
		return err
	}
	if err := os.Remove(snapshot.Path); err != nil {
		return ErrGuestStaging
	}
	return syncDirectory(filepath.Dir(snapshot.Path))
}

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return ErrGuestStaging
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return ErrGuestStaging
	}
	return nil
}

func encodeBootstrapRecoveryRecord(
	record bootstrapRecoveryRecord,
) ([]byte, error) {
	if validateBootstrapRecoveryRecord(record) != nil {
		return nil, ErrGuestStaging
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > sshBootstrapMaxFile {
		return nil, ErrGuestStaging
	}
	return append(encoded, '\n'), nil
}

func decodeBootstrapRecoveryRecord(
	data []byte,
) (bootstrapRecoveryRecord, error) {
	if len(data) == 0 || len(data) > sshBootstrapMaxFile {
		return bootstrapRecoveryRecord{}, ErrGuestStaging
	}
	var record bootstrapRecoveryRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		validateBootstrapRecoveryRecord(record) != nil {
		return bootstrapRecoveryRecord{}, ErrGuestStaging
	}
	return record, nil
}

func validateBootstrapRecoveryRecord(
	record bootstrapRecoveryRecord,
) error {
	expectedTarget := "kyclash-macos-lab-work"
	if record.Role == PeerRole {
		expectedTarget = "kyclash-macos-lab-peer"
	}
	managementKey, managementErr := parseCanonicalRawED25519(
		record.ManagementPublicKey,
	)
	if record.SchemaVersion != 1 ||
		(record.Role != ClientRole && record.Role != PeerRole) ||
		record.RuntimeTarget != expectedTarget ||
		!validAccountName(record.Console.Name) ||
		record.Console.UID == 0 ||
		record.Console.GID == 0 ||
		record.Console.Home != "/Users/"+record.Console.Name ||
		(record.Console.Shell != "/bin/zsh" &&
			record.Console.Shell != "/bin/bash" &&
			record.Console.Shell != "/bin/sh") ||
		!validSHA256(record.ManagementKeySHA256) ||
		!strings.HasPrefix(record.ManagementKeyFingerprint, "SHA256:") ||
		managementErr != nil ||
		record.ManagementKeySHA256 != hashHex(record.ManagementPublicKey) ||
		record.ManagementKeyFingerprint != ssh.FingerprintSHA256(managementKey) ||
		!record.SSHDPolicyWasAbsent ||
		record.CreatedAt <= 0 ||
		record.ConsoleAuthorizedKeys.Path !=
			filepath.Join(record.Console.Home, ".ssh", "authorized_keys") {
		return ErrGuestStaging
	}
	if record.Role == ClientRole && len(record.PeerHostKeys) != 0 ||
		record.Role == ClientRole && record.RestrictedUserExisted ||
		record.Role == PeerRole &&
			len(record.PeerHostKeys) != len(peerSSHHostKeyPaths) {
		return ErrGuestStaging
	}
	for index, snapshot := range record.PeerHostKeys {
		if snapshot.Path != peerSSHHostKeyPaths[index] ||
			!snapshot.Existed ||
			snapshot.UID != 0 ||
			snapshot.GID != 0 ||
			snapshot.Mode != uint32(expectedSSHHostKeyMode(snapshot.Path)) ||
			!validRecoveryFile(snapshot) {
			return ErrGuestStaging
		}
	}
	if record.ConsoleAuthorizedKeys.Existed &&
		(!validRecoveryFile(record.ConsoleAuthorizedKeys) ||
			record.ConsoleAuthorizedKeys.UID != record.Console.UID ||
			record.ConsoleAuthorizedKeys.GID != record.Console.GID ||
			record.ConsoleAuthorizedKeys.Mode != 0o600) {
		return ErrGuestStaging
	}
	return nil
}

func validRecoveryFile(snapshot recoveryFile) bool {
	return filepath.IsAbs(snapshot.Path) &&
		filepath.Clean(snapshot.Path) == snapshot.Path &&
		snapshot.Device != 0 &&
		snapshot.Inode != 0 &&
		snapshot.Links == 1 &&
		snapshot.Size <= sshBootstrapMaxFile &&
		validSHA256(snapshot.SHA256) &&
		fixedBaseName(snapshot.BackupName)
}

func encodeBootstrapCompletion(
	completion bootstrapCompletion,
) ([]byte, error) {
	if completion.SchemaVersion != 1 ||
		!validSHA256(completion.RecoveryRecordSHA256) ||
		!validSHA256(completion.HostKeySHA256) ||
		!strings.HasPrefix(completion.HostKeyFingerprint, "SHA256:") ||
		completion.CompletedAt <= 0 {
		return nil, ErrGuestStaging
	}
	encoded, err := json.Marshal(completion)
	if err != nil || len(encoded) > sshBootstrapMaxFile {
		return nil, ErrGuestStaging
	}
	return append(encoded, '\n'), nil
}

func decodeBootstrapCompletion(data []byte) (bootstrapCompletion, error) {
	var completion bootstrapCompletion
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if len(data) == 0 ||
		len(data) > sshBootstrapMaxFile ||
		decoder.Decode(&completion) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return bootstrapCompletion{}, ErrGuestStaging
	}
	if _, err := encodeBootstrapCompletion(completion); err != nil {
		return bootstrapCompletion{}, err
	}
	return completion, nil
}

func encodeGeneratedHostKeys(
	record generatedHostKeysRecord,
) ([]byte, error) {
	if validateGeneratedHostKeys(record) != nil {
		return nil, ErrGuestStaging
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > sshBootstrapMaxFile {
		return nil, ErrGuestStaging
	}
	return append(encoded, '\n'), nil
}

func decodeGeneratedHostKeys(
	data []byte,
) (generatedHostKeysRecord, error) {
	if len(data) == 0 || len(data) > sshBootstrapMaxFile {
		return generatedHostKeysRecord{}, ErrGuestStaging
	}
	var record generatedHostKeysRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		validateGeneratedHostKeys(record) != nil {
		return generatedHostKeysRecord{}, ErrGuestStaging
	}
	return record, nil
}

func validateGeneratedHostKeys(record generatedHostKeysRecord) error {
	if record.SchemaVersion != 1 ||
		len(record.Files) != len(peerSSHHostKeyPaths) {
		return ErrGuestStaging
	}
	for index, generated := range record.Files {
		if generated.Path != peerSSHHostKeyPaths[index] ||
			!generated.Existed ||
			generated.UID != 0 ||
			generated.GID != 0 ||
			generated.Mode != uint32(expectedSSHHostKeyMode(generated.Path)) ||
			!validRecoveryFile(generated) {
			return ErrGuestStaging
		}
	}
	return nil
}

func readAndVerifyGeneratedHostKeys(
	paths bootstrapPaths,
) (generatedHostKeysRecord, error) {
	data, _, err := readSafeFile(
		paths.Generated,
		0,
		0,
		0o600,
		sshBootstrapMaxFile,
	)
	if err != nil {
		return generatedHostKeysRecord{}, err
	}
	defer clear(data)
	record, err := decodeGeneratedHostKeys(data)
	if err != nil {
		return generatedHostKeysRecord{}, err
	}
	for _, generated := range record.Files {
		if err := verifyFileMatchesRecovery(generated); err != nil {
			return generatedHostKeysRecord{}, err
		}
	}
	return record, nil
}

func recoverInterruptedBootstrap(
	ctx context.Context,
	request SSHBootstrapRequest,
	console bootstrapAccount,
	paths bootstrapPaths,
) (bool, error) {
	pendingState := paths.State + ".pending"
	if pathAbsent(paths.State) {
		if !pathAbsent(pendingState) {
			if err := removeControlledTree(pendingState, 0, 0); err != nil {
				return false, err
			}
		}
		return false, nil
	}
	if !pathAbsent(pendingState) {
		return false, ErrGuestStaging
	}
	for _, atomicPath := range []string{
		paths.Generated,
		paths.Restricted,
		paths.Complete,
	} {
		temporary := atomicPath + ".pending"
		if !pathAbsent(temporary) {
			if !pathAbsent(atomicPath) ||
				removeKnownAtomicTemporary(
					temporary, 0, 0, 0o600,
				) != nil {
				return false, ErrGuestStaging
			}
		}
	}
	if pathExists(paths.Complete) {
		return false, nil
	}
	recordBytes, _, err := readSafeFile(
		paths.Journal,
		0,
		0,
		0o600,
		sshBootstrapMaxFile,
	)
	if err != nil {
		return false, err
	}
	defer clear(recordBytes)
	record, err := decodeBootstrapRecoveryRecord(recordBytes)
	if err != nil ||
		record.Role != request.Role ||
		record.RuntimeTarget != request.RuntimeTarget ||
		record.Console != console {
		return false, ErrGuestStaging
	}
	if pathExists(paths.Ready) {
		if err := rollbackBootstrap(ctx, record, paths); err != nil {
			return false, err
		}
	} else if err := verifyNoBootstrapMutation(record); err != nil {
		return false, err
	}
	if err := removeRolledBackBootstrapState(paths, record); err != nil {
		return false, err
	}
	return true, nil
}

func verifyNoBootstrapMutation(record bootstrapRecoveryRecord) error {
	if !pathAbsent(sshdDropInPath) {
		return ErrGuestStaging
	}
	if err := verifyFileMatchesRecovery(record.ConsoleAuthorizedKeys); err != nil {
		return err
	}
	for _, snapshot := range record.PeerHostKeys {
		if err := verifyFileMatchesRecovery(snapshot); err != nil {
			return err
		}
	}
	return nil
}

func rollbackBootstrap(
	ctx context.Context,
	record bootstrapRecoveryRecord,
	paths bootstrapPaths,
) error {
	var result error
	if record.Role == PeerRole {
		result = errors.Join(
			result,
			rollbackPeerHostKeys(record, paths),
		)
		if !record.RestrictedUserExisted {
			result = errors.Join(
				result,
				removeRestrictedAccount(ctx, paths),
			)
		}
	}
	result = errors.Join(
		result,
		restoreConsoleAuthorization(record, paths),
	)
	if result != nil {
		// Keep the restrictive drop-in installed whenever any restoration is
		// ambiguous. A partial rollback must fail closed.
		return result
	}
	if pathExists(sshdDropInPath) {
		data, identity, err := readSafeFile(
			sshdDropInPath,
			0,
			0,
			0o600,
			sshBootstrapMaxFile,
		)
		if err != nil ||
			string(data) != expectedSSHDPolicy(record.Role, record.Console.Name) {
			clear(data)
			return ErrGuestStaging
		}
		clear(data)
		snapshot := recoveryFile{
			Path:             sshdDropInPath,
			Existed:          true,
			Device:           identity.Device,
			Inode:            identity.Inode,
			UID:              identity.UID,
			GID:              identity.GID,
			Mode:             identity.Mode,
			Links:            identity.Links,
			Size:             identity.Size,
			ModifiedUnixNano: identity.ModifiedUnixNano,
			SHA256:           identity.SHA256,
			BackupName:       "policy",
		}
		return removeSnapshotExact(snapshot)
	}
	return nil
}

func rollbackPeerHostKeys(
	record bootstrapRecoveryRecord,
	paths bootstrapPaths,
) error {
	if record.Role != PeerRole ||
		len(record.PeerHostKeys) != len(peerSSHHostKeyPaths) {
		return ErrGuestStaging
	}
	if pathExists(paths.Generated) {
		markerData, markerIdentity, err := readSafeFile(
			paths.Generated,
			0,
			0,
			0o600,
			sshBootstrapMaxFile,
		)
		if err != nil {
			return err
		}
		generated, err := decodeGeneratedHostKeys(markerData)
		clear(markerData)
		if err != nil {
			return err
		}
		marker := recoveryFromIdentity(
			paths.Generated,
			markerIdentity,
			"generated-host-keys-marker",
		)
		for index, current := range generated.Files {
			original := record.PeerHostKeys[index]
			stagedPath := filepath.Join(
				paths.HostKeyStaging, filepath.Base(original.Path),
			)
			if !pathAbsent(stagedPath) {
				if verifyFileIdentityAtPath(stagedPath, current) != nil {
					return ErrGuestStaging
				}
			}
			if pathAbsent(original.Path) {
				// Restore after any retained staged replacement is removed.
			} else if verifyFileMatchesRecovery(current) == nil {
				if err := removeSnapshotExact(current); err != nil {
					return err
				}
			} else if verifyFileMatchesRecovery(original) != nil {
				return ErrGuestStaging
			}
			if !pathAbsent(stagedPath) {
				if err := os.Remove(stagedPath); err != nil {
					return ErrGuestStaging
				}
			}
		}
		for _, original := range record.PeerHostKeys {
			if pathAbsent(original.Path) {
				if err := restoreRecoveryFile(
					original, paths.Backups,
				); err != nil {
					return err
				}
			} else if verifyFileMatchesRecovery(original) != nil {
				return ErrGuestStaging
			}
		}
		if !pathAbsent(paths.HostKeyStaging) {
			entries, err := os.ReadDir(paths.HostKeyStaging)
			if err != nil || len(entries) != 0 ||
				os.Remove(paths.HostKeyStaging) != nil {
				return ErrGuestStaging
			}
		}
		if err := removeSnapshotExact(marker); err != nil {
			return err
		}
		return nil
	}
	if !pathAbsent(paths.HostKeyStaging) {
		if err := removeControlledTree(
			paths.HostKeyStaging, 0, 0,
		); err != nil {
			return err
		}
	}
	for _, original := range record.PeerHostKeys {
		if pathAbsent(original.Path) {
			continue
		}
		if err := verifyFileMatchesRecovery(original); err != nil {
			// A generated or foreign replacement without the exact generated
			// witness is ambiguous. Preserve the recovery record and refuse.
			return ErrGuestStaging
		}
	}
	for _, original := range record.PeerHostKeys {
		if pathAbsent(original.Path) {
			if err := restoreRecoveryFile(original, paths.Backups); err != nil {
				return err
			}
		}
	}
	return nil
}

// purgeCompletedPeerHostKeyBackups removes only the pre-bootstrap private
// host-key bytes after the durable completion marker exists. Public-key
// backups and the journal stay available for audit, while retries tolerate a
// private backup that an earlier completed invocation already removed.
func purgeCompletedPeerHostKeyBackups(
	paths bootstrapPaths,
	record bootstrapRecoveryRecord,
) error {
	if record.Role != PeerRole {
		return nil
	}
	if !pathExists(paths.Complete) ||
		len(record.PeerHostKeys) != len(peerSSHHostKeyPaths) {
		return ErrGuestStaging
	}
	for _, snapshot := range record.PeerHostKeys {
		if strings.HasSuffix(snapshot.Path, ".pub") {
			continue
		}
		backupPath := filepath.Join(paths.Backups, snapshot.BackupName)
		if pathAbsent(backupPath) {
			continue
		}
		if err := verifyRecoverySnapshot(snapshot, paths.Backups); err != nil ||
			os.Remove(backupPath) != nil {
			return ErrGuestStaging
		}
	}
	return syncDirectory(paths.Backups)
}

func recoveryFromIdentity(
	path string,
	identity fileIdentity,
	backupName string,
) recoveryFile {
	return recoveryFile{
		Path:             path,
		Existed:          true,
		Device:           identity.Device,
		Inode:            identity.Inode,
		UID:              identity.UID,
		GID:              identity.GID,
		Mode:             identity.Mode,
		Links:            identity.Links,
		Size:             identity.Size,
		ModifiedUnixNano: identity.ModifiedUnixNano,
		SHA256:           identity.SHA256,
		BackupName:       backupName,
	}
}

func restoreRecoveryFile(
	snapshot recoveryFile,
	backupRoot string,
) error {
	if err := verifyRecoverySnapshot(snapshot, backupRoot); err != nil {
		return err
	}
	data, _, err := readSafeFile(
		filepath.Join(backupRoot, snapshot.BackupName),
		0,
		0,
		0o600,
		sshBootstrapMaxFile,
	)
	if err != nil {
		return err
	}
	defer clear(data)
	if !pathAbsent(snapshot.Path) {
		return ErrGuestStaging
	}
	return createSystemFileExclusive(
		snapshot.Path,
		data,
		int(snapshot.UID),
		int(snapshot.GID),
		os.FileMode(snapshot.Mode),
	)
}

func restoreConsoleAuthorization(
	record bootstrapRecoveryRecord,
	paths bootstrapPaths,
) error {
	target := record.ConsoleAuthorizedKeys.Path
	key, err := parseCanonicalRawED25519(record.ManagementPublicKey)
	if err != nil {
		return err
	}
	installed := ssh.MarshalAuthorizedKey(key)
	defer clear(installed)
	if pathExists(target) {
		current, _, readErr := readSafeFile(
			target,
			record.Console.UID,
			record.Console.GID,
			0o600,
			64*1024,
		)
		if readErr != nil {
			clear(current)
			return ErrGuestStaging
		}
		if record.ConsoleAuthorizedKeys.Existed &&
			uint64(len(current)) == record.ConsoleAuthorizedKeys.Size &&
			hashHex(current) == record.ConsoleAuthorizedKeys.SHA256 {
			clear(current)
			return verifyFileMatchesRecovery(record.ConsoleAuthorizedKeys)
		}
		if !bytes.Equal(current, installed) {
			clear(current)
			return ErrGuestStaging
		}
		clear(current)
		if err := os.Remove(target); err != nil {
			return ErrGuestStaging
		}
	} else if record.ConsoleAuthorizedKeys.Existed {
		// Continue to the exact witnessed restore below.
	} else if record.ConsoleSSHDirectoryExisted {
		return nil
	}
	if record.ConsoleAuthorizedKeys.Existed {
		if err := restoreRecoveryFile(
			record.ConsoleAuthorizedKeys,
			paths.Backups,
		); err != nil {
			return err
		}
	}
	if !record.ConsoleSSHDirectoryExisted {
		sshDirectory := filepath.Dir(target)
		entries, err := os.ReadDir(sshDirectory)
		if err != nil || len(entries) != 0 ||
			os.Remove(sshDirectory) != nil {
			return ErrGuestStaging
		}
	}
	return nil
}

func removeRestrictedAccount(
	ctx context.Context,
	paths bootstrapPaths,
) error {
	marker, markerIdentity, err := readSafeFile(
		paths.Restricted,
		0,
		0,
		0o600,
		sshBootstrapMaxFile,
	)
	if err != nil ||
		!bytes.Equal(marker, expectedRestrictedAccountPhase()) {
		clear(marker)
		return ErrGuestStaging
	}
	clear(marker)
	markerSnapshot := recoveryFromIdentity(
		paths.Restricted,
		markerIdentity,
		"restricted-account-phase",
	)
	home := "/Users/" + restrictedSSHAccount
	for _, path := range []string{
		filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(home, ".ssh"),
		home,
	} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return ErrGuestStaging
		}
		if path == filepath.Join(home, ".ssh", "authorized_keys") {
			data, _, readErr := readSafeFile(
				path,
				restrictedSSHUID,
				restrictedSSHGID,
				0o600,
				1,
			)
			if readErr != nil || len(data) != 0 {
				clear(data)
				return ErrGuestStaging
			}
			clear(data)
		} else {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return ErrGuestStaging
			}
			identity, identityErr := identityFromInfo(info)
			expectedMode := uint32(0o750)
			if path == filepath.Join(home, ".ssh") {
				expectedMode = 0o700
			}
			if identityErr != nil ||
				(identity.UID != 0 &&
					identity.UID != restrictedSSHUID) ||
				(identity.GID != 0 &&
					identity.GID != restrictedSSHGID) ||
				identity.Mode != expectedMode {
				return ErrGuestStaging
			}
		}
		if err := os.Remove(path); err != nil {
			return ErrGuestStaging
		}
	}
	users, err := listUserNames(ctx)
	if err != nil {
		return err
	}
	_, exists := users[restrictedSSHAccount]
	if !exists {
		return removeSnapshotExact(markerSnapshot)
	}
	output, err := runFixedCommand(
		ctx,
		"/usr/bin/dscl",
		".",
		"-read",
		"/Users/"+restrictedSSHAccount,
	)
	if err != nil {
		clear(output)
		return err
	}
	fields, err := parseDSCLFields(output)
	clear(output)
	if err != nil ||
		validatePartialRestrictedAccountFields(fields) != nil {
		return ErrGuestStaging
	}
	output, err = runFixedCommand(
		ctx,
		"/usr/bin/dscl",
		".",
		"-delete",
		"/Users/"+restrictedSSHAccount,
	)
	clear(output)
	if err != nil {
		return err
	}
	names, err := listUserNames(ctx)
	if err != nil {
		return err
	}
	if _, exists := names[restrictedSSHAccount]; exists {
		return ErrGuestStaging
	}
	return removeSnapshotExact(markerSnapshot)
}

func removeRolledBackBootstrapState(
	paths bootstrapPaths,
	record bootstrapRecoveryRecord,
) error {
	if pathExists(paths.Complete) {
		return ErrGuestStaging
	}
	for _, path := range []string{paths.Ready} {
		if pathExists(path) {
			if err := os.Remove(path); err != nil {
				return ErrGuestStaging
			}
		}
	}
	if pathExists(paths.Backups) {
		entries, err := os.ReadDir(paths.Backups)
		if err != nil {
			return ErrGuestStaging
		}
		expected := make(map[string]struct{})
		snapshots := append(
			[]recoveryFile{record.ConsoleAuthorizedKeys},
			record.PeerHostKeys...,
		)
		for _, snapshot := range snapshots {
			if snapshot.Existed {
				expected[snapshot.BackupName] = struct{}{}
			}
		}
		if len(entries) != len(expected) {
			return ErrGuestStaging
		}
		for _, entry := range entries {
			if entry.IsDir() {
				return ErrGuestStaging
			}
			if _, ok := expected[entry.Name()]; !ok {
				return ErrGuestStaging
			}
			if err := os.Remove(
				filepath.Join(paths.Backups, entry.Name()),
			); err != nil {
				return ErrGuestStaging
			}
		}
		if err := os.Remove(paths.Backups); err != nil {
			return ErrGuestStaging
		}
	}
	if pathExists(paths.Journal) {
		if err := os.Remove(paths.Journal); err != nil {
			return ErrGuestStaging
		}
	}
	if err := os.Remove(paths.State); err != nil {
		return ErrGuestStaging
	}
	return nil
}
