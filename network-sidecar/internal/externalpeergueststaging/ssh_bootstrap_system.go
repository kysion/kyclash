package externalpeergueststaging

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	sshdMainConfigPath = "/etc/ssh/sshd_config"
	sshdDropInRoot     = "/etc/ssh/sshd_config.d"
	sshdDropInPath     = sshdDropInRoot +
		"/000-net.kysion.kyclash.vm-external-peer-lab.conf"
	sshBootstrapStateRoot = "/private/var/db/" +
		"net.kysion.kyclash.vm-external-peer-lab"
	sshHostED25519PublicPath  = "/etc/ssh/ssh_host_ed25519_key.pub"
	sshBootstrapJournalName   = "recovery-record-v1.json"
	sshBootstrapBackupsName   = "backups"
	sshBootstrapReadyName     = "backups-ready"
	sshBootstrapGeneratedName = "generated-host-keys-v1.json"
	sshBootstrapCompleteName  = "complete-v1.json"
	sshBootstrapMaxFile       = 128 * 1024
)

var peerSSHHostKeyPaths = [...]string{
	"/etc/ssh/ssh_host_ed25519_key",
	"/etc/ssh/ssh_host_ed25519_key.pub",
	"/etc/ssh/ssh_host_ecdsa_key",
	"/etc/ssh/ssh_host_ecdsa_key.pub",
	"/etc/ssh/ssh_host_rsa_key",
	"/etc/ssh/ssh_host_rsa_key.pub",
}

type peerSSHHostKeySpec struct {
	privatePath string
	publicPath  string
	keyType     string
	bits        string
	algorithm   string
}

var peerSSHHostKeySpecs = [...]peerSSHHostKeySpec{
	{
		privatePath: peerSSHHostKeyPaths[0],
		publicPath:  peerSSHHostKeyPaths[1],
		keyType:     "ed25519",
		algorithm:   ssh.KeyAlgoED25519,
	},
	{
		privatePath: peerSSHHostKeyPaths[2],
		publicPath:  peerSSHHostKeyPaths[3],
		keyType:     "ecdsa",
		bits:        "521",
		algorithm:   ssh.KeyAlgoECDSA521,
	},
	{
		privatePath: peerSSHHostKeyPaths[4],
		publicPath:  peerSSHHostKeyPaths[5],
		keyType:     "rsa",
		bits:        "3072",
		algorithm:   ssh.KeyAlgoRSA,
	},
}

func expectedSSHHostKeyMode(path string) os.FileMode {
	if strings.HasSuffix(path, ".pub") {
		return 0o644
	}
	return 0o600
}

type productionSSHBootstrapper struct{}

type bootstrapAccount struct {
	Name  string
	UID   uint32
	GID   uint32
	Home  string
	Shell string
}

type recoveryFile struct {
	Path             string `json:"path"`
	Existed          bool   `json:"existed"`
	Device           uint64 `json:"device,omitempty"`
	Inode            uint64 `json:"inode,omitempty"`
	UID              uint32 `json:"uid,omitempty"`
	GID              uint32 `json:"gid,omitempty"`
	Mode             uint32 `json:"mode,omitempty"`
	Links            uint64 `json:"links,omitempty"`
	Size             uint64 `json:"size,omitempty"`
	ModifiedUnixNano int64  `json:"modified_unix_nano,omitempty"`
	SHA256           string `json:"sha256,omitempty"`
	BackupName       string `json:"backup_name,omitempty"`
}

type bootstrapRecoveryRecord struct {
	SchemaVersion              uint8            `json:"schema_version"`
	Role                       Role             `json:"role"`
	RuntimeTarget              string           `json:"runtime_target"`
	Console                    bootstrapAccount `json:"console"`
	ManagementKeySHA256        string           `json:"management_public_key_sha256"`
	ManagementKeyFingerprint   string           `json:"management_public_key_fingerprint"`
	ManagementPublicKey        []byte           `json:"management_public_key"`
	ConsoleSSHDirectoryExisted bool             `json:"console_ssh_directory_existed"`
	ConsoleAuthorizedKeys      recoveryFile     `json:"console_authorized_keys"`
	RestrictedUserExisted      bool             `json:"restricted_user_existed"`
	SSHDPolicyWasAbsent        bool             `json:"sshd_policy_was_absent"`
	PeerHostKeys               []recoveryFile   `json:"peer_host_keys,omitempty"`
	CreatedAt                  int64            `json:"created_at"`
}

type bootstrapCompletion struct {
	SchemaVersion        uint8  `json:"schema_version"`
	RecoveryRecordSHA256 string `json:"recovery_record_sha256"`
	HostKeySHA256        string `json:"host_public_key_sha256"`
	HostKeyFingerprint   string `json:"host_public_key_fingerprint"`
	CompletedAt          int64  `json:"completed_at"`
}

type generatedHostKeysRecord struct {
	SchemaVersion uint8          `json:"schema_version"`
	Files         []recoveryFile `json:"files"`
}

type bootstrapPaths struct {
	State          string
	Journal        string
	Backups        string
	Ready          string
	Generated      string
	HostKeyStaging string
	Restricted     string
	Complete       string
}

func (productionSSHBootstrapper) Bootstrap(
	ctx context.Context,
	request SSHBootstrapRequest,
) (SSHBootstrapResult, error) {
	return bootstrapProductionSSH(ctx, request)
}

func bootstrapProductionSSH(
	ctx context.Context,
	request SSHBootstrapRequest,
) (result SSHBootstrapResult, resultErr error) {
	if ctx == nil || validateSSHBootstrapRequest(request) != nil {
		return SSHBootstrapResult{}, ErrGuestStaging
	}
	console, err := readConsoleAccount(ctx, request)
	if err != nil {
		return SSHBootstrapResult{}, err
	}
	paths := fixedBootstrapPaths(request.Role)
	if recovered, err := recoverInterruptedBootstrap(ctx, request, console, paths); err != nil {
		return SSHBootstrapResult{}, err
	} else if recovered {
		return SSHBootstrapResult{}, ErrGuestStaging
	}
	if pathExists(paths.Complete) {
		return verifyCompletedBootstrap(ctx, request, console, paths)
	}
	if !pathAbsent(paths.State) || !pathAbsent(sshdDropInPath) {
		return SSHBootstrapResult{}, ErrGuestStaging
	}
	if err := verifyRemoteLoginEnabled(ctx); err != nil {
		return SSHBootstrapResult{}, err
	}
	if err := verifySSHDIncludeBoundary(); err != nil {
		return SSHBootstrapResult{}, err
	}
	record, backups, err := buildBootstrapRecoveryRecord(ctx, request, console)
	if err != nil {
		return SSHBootstrapResult{}, err
	}
	defer func() {
		for index := range backups {
			clear(backups[index])
		}
	}()
	recordBytes, err := encodeBootstrapRecoveryRecord(record)
	if err != nil {
		return SSHBootstrapResult{}, err
	}
	defer clear(recordBytes)
	if err := createBootstrapState(paths, record, recordBytes, backups); err != nil {
		return SSHBootstrapResult{}, err
	}
	committed := false
	defer func() {
		if !committed && resultErr != nil {
			if rollbackErr := rollbackBootstrap(
				context.Background(),
				record,
				paths,
			); rollbackErr == nil {
				_ = removeRolledBackBootstrapState(paths, record)
			}
		}
	}()

	key, err := parseCanonicalRawED25519(request.ManagementPublicKey)
	if err != nil {
		return SSHBootstrapResult{}, err
	}
	authorizedKey := ssh.MarshalAuthorizedKey(key)
	defer clear(authorizedKey)
	if err := installConsoleAuthorizedKey(console, record, authorizedKey); err != nil {
		return SSHBootstrapResult{}, err
	}
	if request.Role == PeerRole {
		if err := ensureRestrictedAccount(
			ctx,
			record.RestrictedUserExisted,
			paths,
		); err != nil {
			return SSHBootstrapResult{}, err
		}
	}
	policy := expectedSSHDPolicy(request.Role, console.Name)
	if err := createSystemFileExclusive(
		sshdDropInPath,
		[]byte(policy),
		0,
		0,
		0o600,
	); err != nil {
		return SSHBootstrapResult{}, err
	}
	if request.Role == PeerRole {
		if err := regeneratePeerHostKeys(ctx, record, paths); err != nil {
			return SSHBootstrapResult{}, err
		}
	}
	if err := verifyBootstrapState(ctx, request, console, authorizedKey); err != nil {
		return SSHBootstrapResult{}, err
	}
	hostRaw, hostFingerprint, err := readCanonicalSystemHostPublicKey()
	if err != nil {
		return SSHBootstrapResult{}, err
	}
	defer func() {
		if resultErr != nil {
			clear(hostRaw)
		}
	}()
	completion := bootstrapCompletion{
		SchemaVersion:        1,
		RecoveryRecordSHA256: hashHex(recordBytes),
		HostKeySHA256:        hashHex(hostRaw),
		HostKeyFingerprint:   hostFingerprint,
		CompletedAt:          time.Now().UTC().Unix(),
	}
	completionBytes, err := encodeBootstrapCompletion(completion)
	if err != nil {
		return SSHBootstrapResult{}, err
	}
	defer clear(completionBytes)
	if err := createSystemFileAtomic(
		paths.Complete,
		completionBytes,
		0,
		0,
		0o600,
	); err != nil {
		return SSHBootstrapResult{}, err
	}
	committed = true
	if err := purgeCompletedPeerHostKeyBackups(paths, record); err != nil {
		return SSHBootstrapResult{}, err
	}
	result = buildBootstrapResult(
		request,
		console,
		authorizedKey,
		hostRaw,
		hostFingerprint,
		completion,
	)
	return result, nil
}

func validateSSHBootstrapRequest(request SSHBootstrapRequest) error {
	expectedTarget := "kyclash-macos-lab-work"
	if request.Role == PeerRole {
		expectedTarget = "kyclash-macos-lab-peer"
	}
	key, err := parseCanonicalRawED25519(request.ManagementPublicKey)
	if err != nil ||
		request.RuntimeTarget != expectedTarget ||
		request.ConsoleUID == 0 ||
		request.ManagementKeySHA256 != hashHex(request.ManagementPublicKey) ||
		request.ManagementKeyFingerprint != ssh.FingerprintSHA256(key) {
		return ErrGuestStaging
	}
	return nil
}

func fixedBootstrapPaths(role Role) bootstrapPaths {
	state := filepath.Join(
		sshBootstrapStateRoot,
		"ssh-bootstrap-"+string(role)+"-v1",
	)
	return bootstrapPaths{
		State:          state,
		Journal:        filepath.Join(state, sshBootstrapJournalName),
		Backups:        filepath.Join(state, sshBootstrapBackupsName),
		Ready:          filepath.Join(state, sshBootstrapReadyName),
		Generated:      filepath.Join(state, sshBootstrapGeneratedName),
		HostKeyStaging: filepath.Join(state, "host-key-staging-v1"),
		Restricted:     filepath.Join(state, "restricted-account-phase-v1"),
		Complete:       filepath.Join(state, sshBootstrapCompleteName),
	}
}

func bootstrapPathsForState(state string) bootstrapPaths {
	return bootstrapPaths{
		State:          state,
		Journal:        filepath.Join(state, sshBootstrapJournalName),
		Backups:        filepath.Join(state, sshBootstrapBackupsName),
		Ready:          filepath.Join(state, sshBootstrapReadyName),
		Generated:      filepath.Join(state, sshBootstrapGeneratedName),
		HostKeyStaging: filepath.Join(state, "host-key-staging-v1"),
		Restricted:     filepath.Join(state, "restricted-account-phase-v1"),
		Complete:       filepath.Join(state, sshBootstrapCompleteName),
	}
}

func readConsoleAccount(
	ctx context.Context,
	request SSHBootstrapRequest,
) (bootstrapAccount, error) {
	output, err := runFixedCommand(
		ctx,
		"/usr/bin/stat",
		"-f",
		"%Su",
		"/dev/console",
	)
	if err != nil {
		return bootstrapAccount{}, err
	}
	name := strings.TrimSpace(string(output))
	clear(output)
	if !validAccountName(name) || name == "root" ||
		name == restrictedSSHAccount {
		return bootstrapAccount{}, ErrGuestStaging
	}
	recordOutput, err := runFixedCommand(
		ctx,
		"/usr/bin/dscl",
		".",
		"-read",
		"/Users/"+name,
		"NFSHomeDirectory",
		"PrimaryGroupID",
		"UniqueID",
		"UserShell",
	)
	if err != nil {
		return bootstrapAccount{}, err
	}
	fields, err := parseDSCLFields(recordOutput)
	clear(recordOutput)
	if err != nil {
		return bootstrapAccount{}, err
	}
	uid, uidErr := parseUint32Field(fields, "UniqueID")
	gid, gidErr := parseUint32Field(fields, "PrimaryGroupID")
	home := singleField(fields, "NFSHomeDirectory")
	shell := singleField(fields, "UserShell")
	if uidErr != nil ||
		gidErr != nil ||
		uid != request.ConsoleUID ||
		gid != request.ConsoleGID ||
		home != "/Users/"+name ||
		(shell != "/bin/zsh" && shell != "/bin/bash" && shell != "/bin/sh") {
		return bootstrapAccount{}, ErrGuestStaging
	}
	if err := requireSafeDirectory(home, uid, gid, 0); err != nil {
		return bootstrapAccount{}, err
	}
	return bootstrapAccount{
		Name:  name,
		UID:   uid,
		GID:   gid,
		Home:  home,
		Shell: shell,
	}, nil
}

func verifyRemoteLoginEnabled(ctx context.Context) error {
	output, err := runFixedCommand(
		ctx,
		"/usr/sbin/systemsetup",
		"-getremotelogin",
	)
	if err != nil {
		return err
	}
	enabled := strings.TrimSpace(string(output)) == "Remote Login: On"
	clear(output)
	if !enabled {
		return ErrGuestStaging
	}
	return nil
}

func verifySSHDIncludeBoundary() error {
	data, _, err := readSafeFile(
		sshdMainConfigPath,
		0,
		0,
		0,
		sshBootstrapMaxFile,
	)
	if err != nil {
		return err
	}
	defer clear(data)
	if err := validateSSHDMainConfig(data); err != nil {
		return err
	}
	if err := requireSafeDirectory(sshdDropInRoot, 0, 0, 0); err != nil {
		return err
	}
	entries, err := os.ReadDir(sshdDropInRoot)
	if err != nil {
		return ErrGuestStaging
	}
	ourName := filepath.Base(sshdDropInPath)
	for _, entry := range entries {
		if entry.Name() >= ourName ||
			!strings.HasSuffix(strings.ToLower(entry.Name()), ".conf") {
			continue
		}
		path := filepath.Join(sshdDropInRoot, entry.Name())
		info, statErr := os.Lstat(path)
		if statErr != nil ||
			info.Mode()&os.ModeSymlink != 0 ||
			!info.Mode().IsRegular() {
			return ErrGuestStaging
		}
		fragment, _, readErr := readSafeFile(
			path,
			0,
			0,
			0,
			sshBootstrapMaxFile,
		)
		if readErr != nil ||
			validateEarlierSSHDFragment(fragment) != nil {
			clear(fragment)
			return ErrGuestStaging
		}
		clear(fragment)
	}
	return nil
}

func validateSSHDMainConfig(data []byte) error {
	if len(data) == 0 ||
		len(data) > sshBootstrapMaxFile ||
		bytes.Contains(data, []byte{0}) {
		return ErrGuestStaging
	}
	includeSeen := false
	matchSeen := false
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.EqualFold(fields[0], "Match") {
			matchSeen = true
			continue
		}
		if len(fields) > 0 && strings.EqualFold(fields[0], "Include") {
			if matchSeen ||
				includeSeen ||
				len(fields) != 2 ||
				fields[1] != "/etc/ssh/sshd_config.d/*" {
				return ErrGuestStaging
			}
			includeSeen = true
			continue
		}
		if !includeSeen &&
			len(fields) > 0 &&
			controlledSSHDDirective(fields[0]) {
			return ErrGuestStaging
		}
	}
	if !includeSeen {
		return ErrGuestStaging
	}
	return nil
}

func validateEarlierSSHDFragment(data []byte) error {
	if len(data) == 0 ||
		len(data) > sshBootstrapMaxFile ||
		bytes.Contains(data, []byte{0}) {
		return ErrGuestStaging
	}
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "Match") ||
			strings.EqualFold(fields[0], "Include") ||
			controlledSSHDDirective(fields[0]) {
			return ErrGuestStaging
		}
	}
	return nil
}

func controlledSSHDDirective(value string) bool {
	switch strings.ToLower(value) {
	case "authenticationmethods",
		"pubkeyauthentication",
		"passwordauthentication",
		"kbdinteractiveauthentication",
		"challengeresponseauthentication",
		"permitrootlogin",
		"disableforwarding",
		"allowagentforwarding",
		"allowtcpforwarding",
		"x11forwarding",
		"gatewayports",
		"permittunnel",
		"allowstreamlocalforwarding",
		"allowusers":
		return true
	default:
		return false
	}
}

func buildBootstrapRecoveryRecord(
	ctx context.Context,
	request SSHBootstrapRequest,
	console bootstrapAccount,
) (bootstrapRecoveryRecord, [][]byte, error) {
	sshDirectory := filepath.Join(console.Home, ".ssh")
	sshDirectoryExisted := pathExists(sshDirectory)
	if sshDirectoryExisted {
		if err := requireSafeDirectory(
			sshDirectory,
			console.UID,
			console.GID,
			0o700,
		); err != nil {
			return bootstrapRecoveryRecord{}, nil, err
		}
	}
	authorizedPath := filepath.Join(sshDirectory, "authorized_keys")
	authorized, authorizedBytes, err := snapshotOptionalFile(
		authorizedPath,
		console.UID,
		console.GID,
		0o600,
		64*1024,
		"console-authorized-keys",
		true,
	)
	if err != nil {
		return bootstrapRecoveryRecord{}, nil, err
	}
	backups := [][]byte{authorizedBytes}
	restrictedExisted := false
	if request.Role == PeerRole {
		restrictedExisted, err = inspectRestrictedAccount(ctx)
		if err != nil {
			clear(authorizedBytes)
			return bootstrapRecoveryRecord{}, nil, err
		}
	}
	record := bootstrapRecoveryRecord{
		SchemaVersion:            1,
		Role:                     request.Role,
		RuntimeTarget:            request.RuntimeTarget,
		Console:                  console,
		ManagementKeySHA256:      request.ManagementKeySHA256,
		ManagementKeyFingerprint: request.ManagementKeyFingerprint,
		ManagementPublicKey: append(
			[]byte(nil), request.ManagementPublicKey...,
		),
		ConsoleSSHDirectoryExisted: sshDirectoryExisted,
		ConsoleAuthorizedKeys:      authorized,
		RestrictedUserExisted:      restrictedExisted,
		SSHDPolicyWasAbsent:        pathAbsent(sshdDropInPath),
		CreatedAt:                  time.Now().UTC().Unix(),
	}
	if !record.SSHDPolicyWasAbsent {
		clear(authorizedBytes)
		return bootstrapRecoveryRecord{}, nil, ErrGuestStaging
	}
	if request.Role == PeerRole {
		for index, path := range peerSSHHostKeyPaths {
			snapshot, data, snapshotErr := snapshotOptionalFile(
				path,
				0,
				0,
				expectedSSHHostKeyMode(path),
				sshBootstrapMaxFile,
				fmt.Sprintf("host-key-%02d", index),
				false,
			)
			if snapshotErr != nil || !snapshot.Existed {
				clear(authorizedBytes)
				for backupIndex := 1; backupIndex < len(backups); backupIndex++ {
					clear(backups[backupIndex])
				}
				return bootstrapRecoveryRecord{}, nil, ErrGuestStaging
			}
			record.PeerHostKeys = append(record.PeerHostKeys, snapshot)
			backups = append(backups, data)
		}
	}
	return record, backups, nil
}

func createBootstrapState(
	paths bootstrapPaths,
	record bootstrapRecoveryRecord,
	recordBytes []byte,
	backups [][]byte,
) error {
	if len(backups) != 1+len(record.PeerHostKeys) {
		return ErrGuestStaging
	}
	if err := ensureRootPrivateStateParent(); err != nil {
		return err
	}
	pendingState := paths.State + ".pending"
	if !pathAbsent(paths.State) || !pathAbsent(pendingState) {
		return ErrGuestStaging
	}
	pending := bootstrapPathsForState(pendingState)
	if err := os.Mkdir(pending.State, 0o700); err != nil ||
		os.Chown(pending.State, 0, 0) != nil ||
		os.Chmod(pending.State, 0o700) != nil {
		return ErrGuestStaging
	}
	if err := os.Mkdir(pending.Backups, 0o700); err != nil ||
		os.Chown(pending.Backups, 0, 0) != nil ||
		os.Chmod(pending.Backups, 0o700) != nil {
		return ErrGuestStaging
	}
	if err := createSystemFileExclusive(
		pending.Journal,
		recordBytes,
		0,
		0,
		0o600,
	); err != nil {
		return err
	}
	allSnapshots := append(
		[]recoveryFile{record.ConsoleAuthorizedKeys},
		record.PeerHostKeys...,
	)
	for index, snapshot := range allSnapshots {
		if !snapshot.Existed {
			continue
		}
		if hashHex(backups[index]) != snapshot.SHA256 ||
			uint64(len(backups[index])) != snapshot.Size {
			return ErrGuestStaging
		}
		if err := createSystemFileExclusive(
			filepath.Join(pending.Backups, snapshot.BackupName),
			backups[index],
			0,
			0,
			0o600,
		); err != nil {
			return err
		}
	}
	if err := createSystemFileExclusive(
		pending.Ready,
		[]byte(hashHex(recordBytes)+"\n"),
		0,
		0,
		0o600,
	); err != nil {
		return err
	}
	if syncDirectory(pending.Backups) != nil ||
		syncDirectory(pending.State) != nil ||
		os.Rename(pending.State, paths.State) != nil ||
		syncDirectory(filepath.Dir(paths.State)) != nil {
		return ErrGuestStaging
	}
	return nil
}

func ensureRootPrivateStateParent() error {
	if pathAbsent(sshBootstrapStateRoot) {
		if err := os.Mkdir(sshBootstrapStateRoot, 0o700); err != nil ||
			os.Chown(sshBootstrapStateRoot, 0, 0) != nil ||
			os.Chmod(sshBootstrapStateRoot, 0o700) != nil {
			return ErrGuestStaging
		}
	}
	return requireSafeDirectory(sshBootstrapStateRoot, 0, 0, 0o700)
}

func installConsoleAuthorizedKey(
	console bootstrapAccount,
	record bootstrapRecoveryRecord,
	authorizedKey []byte,
) error {
	sshDirectory := filepath.Join(console.Home, ".ssh")
	if !record.ConsoleSSHDirectoryExisted {
		if !pathAbsent(sshDirectory) ||
			os.Mkdir(sshDirectory, 0o700) != nil ||
			os.Chown(sshDirectory, int(console.UID), int(console.GID)) != nil ||
			os.Chmod(sshDirectory, 0o700) != nil {
			return ErrGuestStaging
		}
	}
	if err := requireSafeDirectory(
		sshDirectory,
		console.UID,
		console.GID,
		0o700,
	); err != nil {
		return err
	}
	return replaceOwnedFile(
		filepath.Join(sshDirectory, "authorized_keys"),
		record.ConsoleAuthorizedKeys,
		authorizedKey,
		console.UID,
		console.GID,
		0o600,
	)
}

func inspectRestrictedAccount(ctx context.Context) (bool, error) {
	users, err := listUserIDs(ctx)
	if err != nil {
		return false, err
	}
	for name, uid := range users {
		if uid == restrictedSSHUID && name != restrictedSSHAccount {
			return false, ErrGuestStaging
		}
	}
	uid, exists := users[restrictedSSHAccount]
	if !exists {
		return false, nil
	}
	if uid != restrictedSSHUID {
		return false, ErrGuestStaging
	}
	if err := verifyRestrictedAccount(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func ensureRestrictedAccount(
	ctx context.Context,
	existed bool,
	paths bootstrapPaths,
) error {
	if existed {
		if !pathAbsent(paths.Restricted) {
			return ErrGuestStaging
		}
		return verifyRestrictedAccount(ctx)
	}
	if pathExists("/Users/" + restrictedSSHAccount) {
		return ErrGuestStaging
	}
	users, err := listUserIDs(ctx)
	if err != nil {
		return err
	}
	for name, uid := range users {
		if name == restrictedSSHAccount || uid == restrictedSSHUID {
			return ErrGuestStaging
		}
	}
	if !pathAbsent(paths.Restricted) {
		return ErrGuestStaging
	}
	if err := createSystemFileAtomic(
		paths.Restricted,
		expectedRestrictedAccountPhase(),
		0,
		0,
		0o600,
	); err != nil {
		return err
	}
	record := "/Users/" + restrictedSSHAccount
	commands := [][]string{
		{"/usr/bin/dscl", ".", "-create", record},
		{"/usr/bin/dscl", ".", "-create", record, "UniqueID", strconv.Itoa(restrictedSSHUID)},
		{"/usr/bin/dscl", ".", "-create", record, "PrimaryGroupID", strconv.Itoa(restrictedSSHGID)},
		{"/usr/bin/dscl", ".", "-create", record, "NFSHomeDirectory", "/Users/" + restrictedSSHAccount},
		{"/usr/bin/dscl", ".", "-create", record, "UserShell", "/bin/sh"},
		{"/usr/bin/dscl", ".", "-create", record, "RealName", "KyClash restricted SSH proof"},
		{"/usr/bin/dscl", ".", "-create", record, "Password", "*"},
		{"/usr/bin/dscl", ".", "-create", record, "AuthenticationAuthority", ";DisabledUser;"},
	}
	for _, command := range commands {
		if output, err := runFixedCommand(ctx, command[0], command[1:]...); err != nil {
			clear(output)
			return ErrGuestStaging
		} else {
			clear(output)
		}
	}
	home := "/Users/" + restrictedSSHAccount
	sshDirectory := filepath.Join(home, ".ssh")
	if os.Mkdir(home, 0o750) != nil ||
		os.Chown(home, restrictedSSHUID, restrictedSSHGID) != nil ||
		os.Chmod(home, 0o750) != nil ||
		os.Mkdir(sshDirectory, 0o700) != nil ||
		os.Chown(sshDirectory, restrictedSSHUID, restrictedSSHGID) != nil ||
		os.Chmod(sshDirectory, 0o700) != nil {
		return ErrGuestStaging
	}
	if err := createSystemFileExclusive(
		filepath.Join(sshDirectory, "authorized_keys"),
		nil,
		restrictedSSHUID,
		restrictedSSHGID,
		0o600,
	); err != nil {
		return err
	}
	return verifyRestrictedAccount(ctx)
}

func expectedRestrictedAccountPhase() []byte {
	return []byte(
		"schema_version=1\n" +
			"account=" + restrictedSSHAccount + "\n" +
			"uid=" + strconv.Itoa(restrictedSSHUID) + "\n" +
			"gid=" + strconv.Itoa(restrictedSSHGID) + "\n" +
			"home=/Users/" + restrictedSSHAccount + "\n",
	)
}

func listUserIDs(ctx context.Context) (map[string]uint32, error) {
	output, err := runFixedCommand(
		ctx,
		"/usr/bin/dscl",
		".",
		"-list",
		"/Users",
		"UniqueID",
	)
	if err != nil {
		return nil, err
	}
	defer clear(output)
	result := make(map[string]uint32)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 || !validDirectoryServiceName(fields[0]) {
			return nil, ErrGuestStaging
		}
		uid, parseErr := strconv.ParseUint(fields[1], 10, 32)
		if parseErr != nil {
			return nil, ErrGuestStaging
		}
		if _, exists := result[fields[0]]; exists {
			return nil, ErrGuestStaging
		}
		result[fields[0]] = uint32(uid)
	}
	if len(result) == 0 {
		return nil, ErrGuestStaging
	}
	return result, nil
}

func listUserNames(ctx context.Context) (map[string]struct{}, error) {
	output, err := runFixedCommand(
		ctx,
		"/usr/bin/dscl",
		".",
		"-list",
		"/Users",
	)
	if err != nil {
		return nil, err
	}
	defer clear(output)
	result := make(map[string]struct{})
	for _, line := range strings.Split(string(output), "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		if !validDirectoryServiceName(name) {
			return nil, ErrGuestStaging
		}
		if _, exists := result[name]; exists {
			return nil, ErrGuestStaging
		}
		result[name] = struct{}{}
	}
	if len(result) == 0 {
		return nil, ErrGuestStaging
	}
	return result, nil
}

func validDirectoryServiceName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character == '_') ||
			(index > 0 && character >= '0' && character <= '9') ||
			(index > 0 && character == '-') {
			continue
		}
		return false
	}
	return true
}

func validatePartialRestrictedAccountFields(
	fields map[string][]string,
) error {
	expectedSingles := map[string]string{
		"RecordName":       restrictedSSHAccount,
		"UniqueID":         strconv.Itoa(restrictedSSHUID),
		"PrimaryGroupID":   strconv.Itoa(restrictedSSHGID),
		"NFSHomeDirectory": "/Users/" + restrictedSSHAccount,
		"UserShell":        "/bin/sh",
		"RealName":         "KyClash restricted SSH proof",
		"Password":         "*",
	}
	for name, expected := range expectedSingles {
		if values, exists := fields[name]; exists &&
			(len(values) != 1 || values[0] != expected) {
			return ErrGuestStaging
		}
	}
	if authorities, exists := fields["AuthenticationAuthority"]; exists {
		if len(authorities) == 0 {
			return ErrGuestStaging
		}
		for _, authority := range authorities {
			if !strings.Contains(authority, "DisabledUser") {
				return ErrGuestStaging
			}
		}
	}
	return nil
}

func verifyRestrictedAccount(ctx context.Context) error {
	output, err := runFixedCommand(
		ctx,
		"/usr/bin/dscl",
		".",
		"-read",
		"/Users/"+restrictedSSHAccount,
		"AuthenticationAuthority",
		"NFSHomeDirectory",
		"Password",
		"PrimaryGroupID",
		"UniqueID",
		"UserShell",
	)
	if err != nil {
		return err
	}
	fields, err := parseDSCLFields(output)
	clear(output)
	if err != nil {
		return err
	}
	uid, uidErr := parseUint32Field(fields, "UniqueID")
	gid, gidErr := parseUint32Field(fields, "PrimaryGroupID")
	if uidErr != nil ||
		gidErr != nil ||
		uid != restrictedSSHUID ||
		gid != restrictedSSHGID ||
		singleField(fields, "NFSHomeDirectory") != "/Users/"+restrictedSSHAccount ||
		singleField(fields, "UserShell") != "/bin/sh" ||
		singleField(fields, "Password") != "*" ||
		!strings.Contains(
			strings.Join(fields["AuthenticationAuthority"], " "),
			"DisabledUser",
		) {
		return ErrGuestStaging
	}
	admin, err := runFixedCommand(
		ctx,
		"/usr/sbin/dseditgroup",
		"-o",
		"checkmember",
		"-m",
		restrictedSSHAccount,
		"admin",
	)
	if err != nil {
		return err
	}
	notAdmin := strings.Contains(string(admin), "NOT a member")
	clear(admin)
	if !notAdmin {
		return ErrGuestStaging
	}
	home := "/Users/" + restrictedSSHAccount
	if err := requireSafeDirectory(home, restrictedSSHUID, restrictedSSHGID, 0o750); err != nil {
		return err
	}
	if err := requireSafeDirectory(
		filepath.Join(home, ".ssh"),
		restrictedSSHUID,
		restrictedSSHGID,
		0o700,
	); err != nil {
		return err
	}
	data, _, err := readSafeFile(
		filepath.Join(home, ".ssh", "authorized_keys"),
		restrictedSSHUID,
		restrictedSSHGID,
		0o600,
		1,
	)
	defer clear(data)
	if err != nil || len(data) != 0 {
		return ErrGuestStaging
	}
	return nil
}

func expectedSSHDPolicy(role Role, consoleUser string) string {
	users := consoleUser
	if role == PeerRole {
		users += " " + restrictedSSHAccount
	}
	return strings.Join([]string{
		"# KyClash disposable two-VM lab; generated by the fixed Layer-A bootstrap.",
		"AuthenticationMethods publickey",
		"PubkeyAuthentication yes",
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"ChallengeResponseAuthentication no",
		"PermitRootLogin no",
		"DisableForwarding yes",
		"AllowAgentForwarding no",
		"AllowTcpForwarding no",
		"AllowStreamLocalForwarding no",
		"X11Forwarding no",
		"GatewayPorts no",
		"PermitTunnel no",
		"AllowUsers " + users,
		"",
	}, "\n")
}

func regeneratePeerHostKeys(
	ctx context.Context,
	record bootstrapRecoveryRecord,
	paths bootstrapPaths,
) error {
	if record.Role != PeerRole ||
		len(record.PeerHostKeys) != len(peerSSHHostKeyPaths) {
		return ErrGuestStaging
	}
	for index, snapshot := range record.PeerHostKeys {
		if snapshot.Path != peerSSHHostKeyPaths[index] ||
			!snapshot.Existed ||
			verifyRecoverySnapshot(snapshot, paths.Backups) != nil {
			return ErrGuestStaging
		}
	}
	if !pathAbsent(paths.HostKeyStaging) {
		return ErrGuestStaging
	}
	if err := os.Mkdir(paths.HostKeyStaging, 0o700); err != nil ||
		os.Chown(paths.HostKeyStaging, 0, 0) != nil ||
		os.Chmod(paths.HostKeyStaging, 0o700) != nil ||
		syncDirectory(paths.State) != nil {
		return ErrGuestStaging
	}
	generated := generatedHostKeysRecord{
		SchemaVersion: 1,
		Files:         make([]recoveryFile, 0, len(record.PeerHostKeys)),
	}
	for _, spec := range peerSSHHostKeySpecs {
		stagedPrivate := filepath.Join(
			paths.HostKeyStaging, filepath.Base(spec.privatePath),
		)
		arguments := []string{
			"-q",
			"-t",
			spec.keyType,
			"-N",
			"",
			"-f",
			stagedPrivate,
		}
		if spec.bits != "" {
			arguments = append(arguments, "-b", spec.bits)
		}
		output, err := runFixedCommand(
			ctx, "/usr/bin/ssh-keygen", arguments...,
		)
		clear(output)
		if err != nil {
			return err
		}
		privateIdentity, publicIdentity, err := verifyGeneratedHostKeyPair(
			ctx,
			stagedPrivate,
			stagedPrivate+".pub",
			spec.algorithm,
		)
		if err != nil {
			return err
		}
		for _, generatedFile := range []struct {
			path     string
			identity fileIdentity
		}{
			{spec.privatePath, privateIdentity},
			{spec.publicPath, publicIdentity},
		} {
			original := record.PeerHostKeys[len(generated.Files)]
			if generatedFile.path != original.Path ||
				generatedFile.identity.SHA256 == original.SHA256 {
				return ErrGuestStaging
			}
			generated.Files = append(generated.Files, recoveryFile{
				Path:             generatedFile.path,
				Existed:          true,
				Device:           generatedFile.identity.Device,
				Inode:            generatedFile.identity.Inode,
				UID:              generatedFile.identity.UID,
				GID:              generatedFile.identity.GID,
				Mode:             generatedFile.identity.Mode,
				Links:            generatedFile.identity.Links,
				Size:             generatedFile.identity.Size,
				ModifiedUnixNano: generatedFile.identity.ModifiedUnixNano,
				SHA256:           generatedFile.identity.SHA256,
				BackupName: "generated-" +
					filepath.Base(generatedFile.path),
			})
		}
	}
	if syncTreeDirectories(paths.HostKeyStaging) != nil {
		return ErrGuestStaging
	}
	encoded, err := encodeGeneratedHostKeys(generated)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if err := createSystemFileAtomic(
		paths.Generated,
		encoded,
		0,
		0,
		0o600,
	); err != nil {
		return err
	}
	// Publish each public half before its private half. The durable generated
	// manifest exists first, so recovery can classify every path as original,
	// generated, staged, or absent after any interruption.
	for _, index := range []int{1, 0, 3, 2, 5, 4} {
		original := record.PeerHostKeys[index]
		replacement := generated.Files[index]
		stagedPath := filepath.Join(
			paths.HostKeyStaging, filepath.Base(original.Path),
		)
		if err := verifyFileIdentityAtPath(stagedPath, replacement); err != nil ||
			verifyFileMatchesRecovery(original) != nil {
			return ErrGuestStaging
		}
		if err := os.Rename(stagedPath, original.Path); err != nil ||
			syncDirectory(filepath.Dir(original.Path)) != nil ||
			verifyFileMatchesRecovery(replacement) != nil {
			return ErrGuestStaging
		}
	}
	if entries, err := os.ReadDir(paths.HostKeyStaging); err != nil ||
		len(entries) != 0 ||
		os.Remove(paths.HostKeyStaging) != nil ||
		syncDirectory(paths.State) != nil {
		return ErrGuestStaging
	}
	return nil
}

func verifyGeneratedHostKeyPair(
	ctx context.Context,
	privatePath string,
	publicPath string,
	algorithm string,
) (fileIdentity, fileIdentity, error) {
	privateBytes, privateIdentity, err := readSafeFile(
		privatePath, 0, 0, 0o600, sshBootstrapMaxFile,
	)
	if err != nil || len(privateBytes) == 0 {
		clear(privateBytes)
		return fileIdentity{}, fileIdentity{}, ErrGuestStaging
	}
	clear(privateBytes)
	publicBytes, publicIdentity, err := readSafeFile(
		publicPath, 0, 0, 0o644, sshBootstrapMaxFile,
	)
	if err != nil {
		clear(publicBytes)
		return fileIdentity{}, fileIdentity{}, err
	}
	defer clear(publicBytes)
	publicKey, _, _, rest, err := ssh.ParseAuthorizedKey(publicBytes)
	if err != nil || publicKey == nil ||
		publicKey.Type() != algorithm ||
		len(bytes.TrimSpace(rest)) != 0 {
		return fileIdentity{}, fileIdentity{}, ErrGuestStaging
	}
	derivedBytes, err := runFixedCommand(
		ctx, "/usr/bin/ssh-keygen", "-y", "-f", privatePath,
	)
	if err != nil {
		return fileIdentity{}, fileIdentity{}, err
	}
	defer clear(derivedBytes)
	derived, _, _, derivedRest, err := ssh.ParseAuthorizedKey(derivedBytes)
	if err != nil || derived == nil ||
		derived.Type() != algorithm ||
		len(bytes.TrimSpace(derivedRest)) != 0 ||
		!bytes.Equal(derived.Marshal(), publicKey.Marshal()) {
		return fileIdentity{}, fileIdentity{}, ErrGuestStaging
	}
	return privateIdentity, publicIdentity, nil
}

func verifyBootstrapState(
	ctx context.Context,
	request SSHBootstrapRequest,
	console bootstrapAccount,
	authorizedKey []byte,
) error {
	if err := verifyRemoteLoginEnabled(ctx); err != nil {
		return err
	}
	current, _, err := readSafeFile(
		filepath.Join(console.Home, ".ssh", "authorized_keys"),
		console.UID,
		console.GID,
		0o600,
		64*1024,
	)
	if err != nil || !bytes.Equal(current, authorizedKey) {
		clear(current)
		return ErrGuestStaging
	}
	clear(current)
	policyBytes, _, err := readSafeFile(
		sshdDropInPath,
		0,
		0,
		0o600,
		sshBootstrapMaxFile,
	)
	if err != nil ||
		string(policyBytes) != expectedSSHDPolicy(request.Role, console.Name) {
		clear(policyBytes)
		return ErrGuestStaging
	}
	clear(policyBytes)
	if output, err := runFixedCommand(ctx, "/usr/sbin/sshd", "-t"); err != nil {
		clear(output)
		return ErrGuestStaging
	} else {
		clear(output)
	}
	expectedUsers := console.Name
	contextUsers := []string{console.Name}
	if request.Role == PeerRole {
		expectedUsers += " " + restrictedSSHAccount
		contextUsers = append(contextUsers, restrictedSSHAccount)
		if err := verifyRestrictedAccount(ctx); err != nil {
			return err
		}
		if _, err := readAndVerifyGeneratedHostKeys(
			fixedBootstrapPaths(request.Role),
		); err != nil {
			return err
		}
	}
	for _, user := range contextUsers {
		for _, address := range []string{
			"127.0.0.1",
			"10.88.0.1",
			"10.0.0.1",
			"172.16.0.1",
			"192.168.0.1",
		} {
			if err := verifyEffectiveSSHDContext(
				ctx,
				user,
				address,
				expectedUsers,
			); err != nil {
				return err
			}
		}
	}
	_, _, err = readCanonicalSystemHostPublicKey()
	return err
}

func verifyEffectiveSSHDContext(
	ctx context.Context,
	user string,
	address string,
	expectedUsers string,
) error {
	effective, err := runFixedCommand(
		ctx,
		"/usr/sbin/sshd",
		"-T",
		"-C",
		"user="+user+",host=localhost,addr="+address,
	)
	if err != nil {
		return err
	}
	fields, err := parseSSHDFields(effective)
	clear(effective)
	if err != nil {
		return err
	}
	return validateEffectiveSSHDFields(fields, expectedUsers)
}

func validateEffectiveSSHDFields(
	fields map[string]string,
	expectedUsers string,
) error {
	expected := map[string]string{
		"authenticationmethods":           "publickey",
		"pubkeyauthentication":            "yes",
		"passwordauthentication":          "no",
		"kbdinteractiveauthentication":    "no",
		"challengeresponseauthentication": "no",
		"permitrootlogin":                 "no",
		"disableforwarding":               "yes",
		"allowagentforwarding":            "no",
		"allowtcpforwarding":              "no",
		"allowstreamlocalforwarding":      "no",
		"x11forwarding":                   "no",
		"gatewayports":                    "no",
		"permittunnel":                    "no",
		"allowusers":                      expectedUsers,
	}
	for name, value := range expected {
		if fields[name] != value {
			return ErrGuestStaging
		}
	}
	return nil
}

func readCanonicalSystemHostPublicKey() ([]byte, string, error) {
	data, _, err := readSafeFile(
		sshHostED25519PublicPath,
		0,
		0,
		0,
		sshBootstrapMaxFile,
	)
	if err != nil {
		return nil, "", err
	}
	defer clear(data)
	key, _, options, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil ||
		key == nil ||
		key.Type() != ssh.KeyAlgoED25519 ||
		len(options) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", ErrGuestStaging
	}
	raw := key.Marshal()
	if _, err := parseCanonicalRawED25519(raw); err != nil {
		clear(raw)
		return nil, "", err
	}
	return raw, ssh.FingerprintSHA256(key), nil
}

func verifyCompletedBootstrap(
	ctx context.Context,
	request SSHBootstrapRequest,
	console bootstrapAccount,
	paths bootstrapPaths,
) (SSHBootstrapResult, error) {
	recordBytes, _, err := readSafeFile(
		paths.Journal,
		0,
		0,
		0o600,
		sshBootstrapMaxFile,
	)
	if err != nil {
		return SSHBootstrapResult{}, err
	}
	defer clear(recordBytes)
	record, err := decodeBootstrapRecoveryRecord(recordBytes)
	if err != nil ||
		record.Role != request.Role ||
		record.RuntimeTarget != request.RuntimeTarget ||
		record.Console != console {
		return SSHBootstrapResult{}, ErrGuestStaging
	}
	completionBytes, _, err := readSafeFile(
		paths.Complete,
		0,
		0,
		0o600,
		sshBootstrapMaxFile,
	)
	if err != nil {
		return SSHBootstrapResult{}, err
	}
	defer clear(completionBytes)
	completion, err := decodeBootstrapCompletion(completionBytes)
	if err != nil ||
		completion.RecoveryRecordSHA256 != hashHex(recordBytes) {
		return SSHBootstrapResult{}, ErrGuestStaging
	}
	key, err := parseCanonicalRawED25519(record.ManagementPublicKey)
	if err != nil {
		return SSHBootstrapResult{}, err
	}
	authorized := ssh.MarshalAuthorizedKey(key)
	defer clear(authorized)
	durableRequest := request
	durableRequest.ManagementPublicKey = record.ManagementPublicKey
	durableRequest.ManagementKeySHA256 = record.ManagementKeySHA256
	durableRequest.ManagementKeyFingerprint = record.ManagementKeyFingerprint
	if err := verifyBootstrapState(
		ctx,
		durableRequest,
		console,
		authorized,
	); err != nil {
		return SSHBootstrapResult{}, err
	}
	hostRaw, fingerprint, err := readCanonicalSystemHostPublicKey()
	if err != nil ||
		hashHex(hostRaw) != completion.HostKeySHA256 ||
		fingerprint != completion.HostKeyFingerprint {
		clear(hostRaw)
		return SSHBootstrapResult{}, ErrGuestStaging
	}
	if err := purgeCompletedPeerHostKeyBackups(paths, record); err != nil {
		clear(hostRaw)
		return SSHBootstrapResult{}, err
	}
	return buildBootstrapResult(
		durableRequest,
		console,
		authorized,
		hostRaw,
		fingerprint,
		completion,
	), nil
}

func buildBootstrapResult(
	request SSHBootstrapRequest,
	console bootstrapAccount,
	authorized []byte,
	hostRaw []byte,
	hostFingerprint string,
	completion bootstrapCompletion,
) SSHBootstrapResult {
	allowed := []string{console.Name}
	restricted := false
	regenerated := false
	if request.Role == PeerRole {
		allowed = append(allowed, restrictedSSHAccount)
		restricted = true
		regenerated = true
	}
	return SSHBootstrapResult{
		HostPublicKey: hostRaw,
		Evidence: SSHBootstrapEvidence{
			SchemaVersion:             1,
			Role:                      request.Role,
			RuntimeTarget:             request.RuntimeTarget,
			ConsoleUser:               console.Name,
			ConsoleUID:                console.UID,
			ConsoleGID:                console.GID,
			RemoteLoginVerified:       true,
			PublicKeyOnlyVerified:     true,
			ForwardingDisabled:        true,
			RootLoginDisabled:         true,
			AllowedUsers:              allowed,
			ManagementKeySHA256:       request.ManagementKeySHA256,
			ManagementKeyFingerprint:  request.ManagementKeyFingerprint,
			AuthorizedKeysSHA256:      hashHex(authorized),
			HostKeySHA256:             hashHex(hostRaw),
			HostKeyFingerprint:        hostFingerprint,
			RestrictedAccountVerified: restricted,
			PeerHostKeysRegenerated:   regenerated,
			RecoveryRecordSHA256:      completion.RecoveryRecordSHA256,
			CompletedAt:               completion.CompletedAt,
		},
	}
}
