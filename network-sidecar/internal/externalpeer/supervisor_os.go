package externalpeer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

type OSPerRunOperations struct {
	mu        sync.Mutex
	staging   PeerStagingManifest
	config    PeerSupervisorConfig
	validated *ValidatedPeerRun
	inbox     *StableDirectory
	outbox    *StableDirectory
	process   *PeerChildProcess
	ready     *PeerChildReady
}

func (operations *OSPerRunOperations) ProcessDone() <-chan error {
	operations.mu.Lock()
	defer operations.mu.Unlock()
	if operations.process == nil {
		return nil
	}
	return operations.process.Done()
}

func (operations *OSPerRunOperations) ValidateRuntimeListeners(
	ctx context.Context,
	baseline PeerListenerBaseline,
) error {
	operations.mu.Lock()
	if operations.process == nil || operations.ready == nil {
		operations.mu.Unlock()
		return ErrListenerAudit
	}
	process := operations.process
	descriptor := operations.ready.Descriptor
	descriptor.Endpoints = append(
		[]profile.Endpoint(nil),
		descriptor.Endpoints...,
	)
	operations.mu.Unlock()
	identity := process.Identity()
	if revalidateChildIdentity(identity) != nil {
		return ErrListenerAudit
	}
	inventory, err := CollectListenerInventory(ctx)
	if err != nil ||
		ValidatePeerRuntimeListenerInventory(
			inventory,
			baseline,
			descriptor,
			identity,
		) != nil ||
		revalidateChildIdentity(identity) != nil {
		return ErrListenerAudit
	}
	return nil
}

func NewOSPerRunOperations(
	staging PeerStagingManifest,
	config PeerSupervisorConfig,
	validated *ValidatedPeerRun,
	inbox *StableDirectory,
	outbox *StableDirectory,
) (*OSPerRunOperations, error) {
	if staging.Validate() != nil ||
		config.Validate() != nil ||
		validated == nil ||
		inbox == nil ||
		outbox == nil {
		return nil, ErrSupervisorState
	}
	return &OSPerRunOperations{
		staging:   staging,
		config:    config,
		validated: validated,
		inbox:     inbox,
		outbox:    outbox,
	}, nil
}

// NewOSRecoveryOperations deliberately has no courier-derived ValidatedPeerRun.
// A retained root journal must remain recoverable after the console-user inbox
// has been consumed, removed, changed, or expired.
func NewOSRecoveryOperations(
	staging PeerStagingManifest,
	config PeerSupervisorConfig,
	inbox *StableDirectory,
	outbox *StableDirectory,
) (*OSPerRunOperations, error) {
	if staging.Validate() != nil ||
		config.Validate() != nil ||
		outbox == nil {
		return nil, ErrSupervisorState
	}
	return &OSPerRunOperations{
		staging: staging,
		config:  config,
		inbox:   inbox,
		outbox:  outbox,
	}, nil
}

func (operations *OSPerRunOperations) ValidateStaging(context.Context) error {
	manifest, err := LoadAndValidatePeerStagingManifest()
	if err != nil || manifest != operations.staging {
		return ErrInvalidStagingManifest
	}
	config, err := LoadPeerSupervisorConfig(manifest)
	if err != nil || config != operations.config {
		return ErrInvalidStagingManifest
	}
	return nil
}

func (operations *OSPerRunOperations) InstallAuthorizedKey(
	_ context.Context,
	run SupervisorRun,
) error {
	operations.mu.Lock()
	defer operations.mu.Unlock()
	if operations.validated == nil ||
		!operations.matchesValidatedRun(run) ||
		run.AuthorizedKeysOriginal == nil {
		return ErrSupervisorState
	}
	return installPreparedAuthorizedKey(
		[]byte(run.AuthorizedKeyLine),
		*run.AuthorizedKeysOriginal,
		operations.config.PeerChildUID,
		operations.config.PeerChildGID,
	)
}

func (operations *OSPerRunOperations) ObserveAuthorizedKey(
	_ context.Context,
	run SupervisorRun,
) (AuthorizedKeysOriginal, error) {
	operations.mu.Lock()
	defer operations.mu.Unlock()
	if operations.validated == nil ||
		!operations.matchesValidatedRun(run) ||
		run.AuthorizedKeysOriginal != nil {
		return AuthorizedKeysOriginal{}, ErrSupervisorState
	}
	return observeAuthorizedKeysOriginal(
		[]byte(run.AuthorizedKeyLine),
		operations.config.PeerChildUID,
		operations.config.PeerChildGID,
	)
}

func (operations *OSPerRunOperations) PrepareAuthorizedKey(
	_ context.Context,
	run SupervisorRun,
) error {
	operations.mu.Lock()
	defer operations.mu.Unlock()
	if operations.validated == nil ||
		!operations.matchesValidatedRun(run) ||
		run.AuthorizedKeysOriginal == nil {
		return ErrSupervisorState
	}
	return prepareAuthorizedKeyWitness(
		[]byte(run.AuthorizedKeyLine),
		*run.AuthorizedKeysOriginal,
		operations.config.PeerChildUID,
		operations.config.PeerChildGID,
	)
}

func (operations *OSPerRunOperations) StartPeerChild(
	ctx context.Context,
	run SupervisorRun,
	onBound func(ChildIdentity) error,
) (ChildIdentity, error) {
	operations.mu.Lock()
	defer operations.mu.Unlock()
	if operations.process != nil ||
		operations.validated == nil ||
		!operations.matchesValidatedRun(run) ||
		onBound == nil {
		return ChildIdentity{}, ErrSupervisorState
	}
	if err := operations.ValidateStaging(ctx); err != nil {
		return ChildIdentity{}, err
	}
	if err := ValidateCurrentPeerRuntime(operations.config); err != nil {
		return ChildIdentity{}, err
	}
	process, ready, err := StartPeerChildProcess(
		ctx,
		operations.config,
		operations.staging.PeerChild,
		operations.validated.PeerConfig,
		operations.validated.ClientDescriptor,
		onBound,
	)
	if err != nil {
		return ChildIdentity{}, err
	}
	if err := publishRunNonce(ready.RunNonce); err != nil {
		_ = process.Stop(context.Background())
		clearPeerChildReady(&ready)
		return ChildIdentity{}, err
	}
	if err := operations.publishPeerOutbox(ready.Artifacts); err != nil {
		_ = process.Stop(context.Background())
		_ = removeRunNonce()
		clearPeerChildReady(&ready)
		return ChildIdentity{}, err
	}
	operations.process = process
	operations.ready = &ready
	return process.Identity(), nil
}

func (operations *OSPerRunOperations) StopPeerChild(
	ctx context.Context,
	identity ChildIdentity,
) error {
	operations.mu.Lock()
	process := operations.process
	operations.mu.Unlock()
	if process == nil {
		return stopBoundChildIdentity(ctx, identity)
	}
	if process.Identity() != identity {
		return ErrSupervisorRecovery
	}
	return process.Stop(ctx)
}

func stopBoundChildIdentity(ctx context.Context, identity ChildIdentity) error {
	if revalidateChildIdentity(identity) != nil {
		err := syscall.Kill(identity.PID, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return ErrSupervisorRecovery
	}
	if err := syscall.Kill(identity.PID, syscall.SIGTERM); err != nil &&
		!errors.Is(err, syscall.ESRCH) {
		return err
	}
	timer := time.NewTicker(50 * time.Millisecond)
	defer timer.Stop()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			err := syscall.Kill(identity.PID, 0)
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
		case <-timeout.C:
			if revalidateChildIdentity(identity) != nil {
				return ErrSupervisorRecovery
			}
			if err := syscall.Kill(identity.PID, syscall.SIGKILL); err != nil &&
				!errors.Is(err, syscall.ESRCH) {
				return err
			}
			return waitForPIDAbsent(ctx, identity.PID, 2*time.Second)
		}
	}
}

func waitForPIDAbsent(
	ctx context.Context,
	pid int,
	timeout time.Duration,
) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return ErrSupervisorRecovery
		case <-ticker.C:
		}
	}
}

func (operations *OSPerRunOperations) RemoveAuthorizedKey(
	_ context.Context,
	run SupervisorRun,
) error {
	if !operations.matchesValidatedRun(run) {
		return ErrSupervisorState
	}
	return removeAuthorizedKeyWitness(
		[]byte(run.AuthorizedKeyLine),
		run.AuthorizedKeysOriginal,
		operations.config.PeerChildUID,
		operations.config.PeerChildGID,
	)
}

func (operations *OSPerRunOperations) RemoveRunArtifacts(
	_ context.Context,
	run SupervisorRun,
) error {
	operations.mu.Lock()
	defer operations.mu.Unlock()
	if !operations.matchesValidatedRun(run) {
		return ErrSupervisorState
	}
	var cleanupErr error
	for _, name := range PeerArtifactNames {
		cleanupErr = errors.Join(
			cleanupErr,
			operations.outbox.RemoveExactMode(name, 0o644),
		)
	}
	cleanupErr = errors.Join(cleanupErr, removeRunNonce())
	for _, name := range PeerInboxRunNames {
		if operations.inbox != nil {
			cleanupErr = errors.Join(
				cleanupErr,
				operations.inbox.RemoveExact(name),
			)
		}
	}
	for _, name := range []string{"cancel-envelope.bin", "cancel-wake"} {
		if _, err := os.Lstat(filepath.Join(PeerCourierInbox, name)); err == nil &&
			operations.inbox != nil {
			cleanupErr = errors.Join(cleanupErr, operations.inbox.RemoveExact(name))
		} else if err == nil {
			cleanupErr = errors.Join(cleanupErr, ErrSupervisorRecovery)
		} else if !errors.Is(err, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if operations.ready != nil {
		clearPeerChildReady(operations.ready)
		operations.ready = nil
	}
	operations.process = nil
	return cleanupErr
}

func (operations *OSPerRunOperations) ProveRunAbsent(
	_ context.Context,
	run SupervisorRun,
	child *ChildIdentity,
) error {
	if !operations.matchesValidatedRun(run) {
		return ErrSupervisorState
	}
	if child != nil {
		err := syscall.Kill(child.PID, 0)
		if err == nil || !errors.Is(err, syscall.ESRCH) {
			return ErrSupervisorRecovery
		}
	}
	if _, err := os.Lstat(PeerRunNoncePath); !errors.Is(err, os.ErrNotExist) {
		return ErrSupervisorRecovery
	}
	if _, err := os.Lstat(PeerAuthorizedKeysWitnessPath); !errors.Is(err, os.ErrNotExist) {
		return ErrSupervisorRecovery
	}
	if _, err := os.Lstat(PeerAuthorizedKeysScratchPath); !errors.Is(err, os.ErrNotExist) {
		return ErrSupervisorRecovery
	}
	for _, name := range PeerArtifactNames {
		if _, err := os.Lstat(filepath.Join(PeerPublicOutbox, name)); !errors.Is(err, os.ErrNotExist) {
			return ErrSupervisorRecovery
		}
	}
	for _, name := range PeerInboxRunNames {
		if _, err := os.Lstat(filepath.Join(PeerCourierInbox, name)); !errors.Is(err, os.ErrNotExist) {
			return ErrSupervisorRecovery
		}
	}
	for _, name := range []string{"cancel-envelope.bin", "cancel-wake"} {
		if _, err := os.Lstat(filepath.Join(PeerCourierInbox, name)); !errors.Is(err, os.ErrNotExist) {
			return ErrSupervisorRecovery
		}
	}
	return proveAuthorizedLineAbsent(
		[]byte(run.AuthorizedKeyLine),
		operations.config.PeerChildUID,
	)
}

func (operations *OSPerRunOperations) matchesValidatedRun(
	run SupervisorRun,
) bool {
	if !validRunID(run.RunID) ||
		!validSHA256(run.TicketHash) ||
		!ValidAuthorizedKeyLine(run.AuthorizedKeyLine) ||
		run.AuthorizedKeysOriginal != nil &&
			run.AuthorizedKeysOriginal.Validate() != nil {
		return false
	}
	if operations.validated == nil {
		return true
	}
	return run.RunID == operations.validated.Run.RunID &&
		run.TicketHash == operations.validated.Run.TicketHash &&
		run.AuthorizedKeyLine == operations.validated.Run.AuthorizedKeyLine
}

func (operations *OSPerRunOperations) publishPeerOutbox(
	artifacts PeerPublicArtifacts,
) error {
	payloads := [][]byte{
		artifacts.Descriptor,
		artifacts.CADER,
		artifacts.ServerCertificateDER,
		artifacts.ClientCertificateDER,
		artifacts.OverlayServerPublicKey,
		artifacts.SystemSSHHostPublicKey,
		artifacts.TransferManifest,
	}
	for index, data := range payloads {
		if err := operations.outbox.CreateExactFile(
			PeerArtifactNames[index],
			data,
			0o644,
		); err != nil {
			for previous := 0; previous < index; previous++ {
				_ = operations.outbox.RemoveExactMode(
					PeerArtifactNames[previous],
					0o644,
				)
			}
			return err
		}
	}
	return nil
}

func observeAuthorizedKeysOriginal(
	line []byte,
	expectedUID uint32,
	expectedGID uint32,
) (AuthorizedKeysOriginal, error) {
	if !ValidAuthorizedKeyLine(string(line)) {
		return AuthorizedKeysOriginal{}, ErrSupervisorState
	}
	original, info, err := readAuthorizedKeys(expectedUID)
	if err != nil {
		return AuthorizedKeysOriginal{}, err
	}
	defer clear(original)
	if bytes.Contains(original, line) ||
		len(original) > 0 && original[len(original)-1] != '\n' {
		return AuthorizedKeysOriginal{}, ErrSupervisorState
	}
	metadata, err := authorizedKeysOriginal(
		info,
		original,
		expectedUID,
		expectedGID,
	)
	if err != nil {
		return AuthorizedKeysOriginal{}, err
	}
	return metadata, nil
}

func prepareAuthorizedKeyWitness(
	line []byte,
	originalMetadata AuthorizedKeysOriginal,
	expectedUID uint32,
	expectedGID uint32,
) error {
	if !ValidAuthorizedKeyLine(string(line)) ||
		originalMetadata.Validate() != nil {
		return ErrSupervisorState
	}
	original, info, err := readAuthorizedKeys(expectedUID)
	if err != nil {
		return err
	}
	defer clear(original)
	if bytes.Contains(original, line) ||
		len(original) > 0 && original[len(original)-1] != '\n' ||
		!authorizedKeysIdentityMatchesOriginal(
			info,
			original,
			originalMetadata,
			true,
			expectedUID,
			expectedGID,
		) {
		return ErrSupervisorRecovery
	}
	if err := writeRootPrivateAtomicCreateOnly(
		PeerAuthorizedKeysWitnessPath,
		PeerAuthorizedKeysScratchPath,
		original,
		0o600,
	); err != nil {
		return err
	}
	current, currentInfo, err := readAuthorizedKeys(expectedUID)
	if err != nil {
		return err
	}
	defer clear(current)
	if !bytes.Equal(current, original) ||
		!os.SameFile(info, currentInfo) ||
		!authorizedKeysIdentityMatchesOriginal(
			currentInfo,
			current,
			originalMetadata,
			true,
			expectedUID,
			expectedGID,
		) {
		return ErrSupervisorRecovery
	}
	return nil
}

func installPreparedAuthorizedKey(
	line []byte,
	original AuthorizedKeysOriginal,
	expectedUID uint32,
	expectedGID uint32,
) error {
	if !ValidAuthorizedKeyLine(string(line)) ||
		original.Validate() != nil {
		return ErrSupervisorState
	}
	witness, err := readRootPrivateExact(
		PeerAuthorizedKeysWitnessPath,
		64*1024,
		0o600,
	)
	if err != nil {
		return err
	}
	defer clear(witness)
	if !authorizedKeysBytesMatchOriginal(
		witness,
		original,
	) {
		return ErrSupervisorRecovery
	}
	current, info, err := readAuthorizedKeys(expectedUID)
	if err != nil {
		return err
	}
	defer clear(current)
	if !bytes.Equal(current, witness) ||
		!authorizedKeysIdentityMatchesOriginal(
			info,
			current,
			original,
			true,
			expectedUID,
			expectedGID,
		) {
		return ErrSupervisorRecovery
	}
	next := make([]byte, 0, len(witness)+len(line))
	next = append(next, witness...)
	next = append(next, line...)
	if err := replaceAuthorizedKeys(
		next,
		info,
		expectedUID,
		expectedGID,
	); err != nil {
		clear(next)
		return err
	}
	installed, installedInfo, err := readAuthorizedKeys(expectedUID)
	if err != nil ||
		!bytes.Equal(installed, next) ||
		!authorizedKeysSafeIdentity(
			installedInfo,
			expectedUID,
			expectedGID,
		) {
		clear(installed)
		clear(next)
		return ErrSupervisorRecovery
	}
	clear(installed)
	clear(next)
	return nil
}

func removeAuthorizedKeyWitness(
	line []byte,
	originalMetadata *AuthorizedKeysOriginal,
	expectedUID uint32,
	expectedGID uint32,
) error {
	if !ValidAuthorizedKeyLine(string(line)) ||
		originalMetadata == nil ||
		originalMetadata.Validate() != nil {
		return ErrSupervisorState
	}
	current, info, err := readAuthorizedKeys(expectedUID)
	if err != nil {
		return err
	}
	defer clear(current)
	if err := reconcileAuthorizedKeysScratch(
		current,
		info,
		originalMetadata,
		expectedUID,
		expectedGID,
	); err != nil {
		return err
	}
	witnessInfo, witnessErr := os.Lstat(PeerAuthorizedKeysWitnessPath)
	if errors.Is(witnessErr, os.ErrNotExist) {
		action, err := decideAuthorizedKeyRecovery(
			current,
			nil,
			line,
			false,
			originalMetadata,
		)
		if err != nil || action != authorizedKeyNoChange {
			return ErrSupervisorRecovery
		}
		if !authorizedKeysIdentityMatchesOriginal(
			info,
			current,
			*originalMetadata,
			false,
			expectedUID,
			expectedGID,
		) {
			return ErrSupervisorRecovery
		}
		return nil
	}
	if witnessErr != nil ||
		!witnessInfo.Mode().IsRegular() ||
		witnessInfo.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeSupervisorFile
	}
	original, err := readRootPrivateExact(
		PeerAuthorizedKeysWitnessPath,
		64*1024,
		0o600,
	)
	if err != nil {
		return err
	}
	defer clear(original)
	action, err := decideAuthorizedKeyRecovery(
		current,
		original,
		line,
		true,
		originalMetadata,
	)
	if err != nil {
		return err
	}
	switch action {
	case authorizedKeyRemoveWitness:
		if !authorizedKeysIdentityMatchesOriginal(
			info,
			current,
			*originalMetadata,
			false,
			expectedUID,
			expectedGID,
		) {
			return ErrSupervisorRecovery
		}
	case authorizedKeyRestoreAndRemoveWitness:
		if err := replaceAuthorizedKeys(
			original,
			info,
			expectedUID,
			expectedGID,
		); err != nil {
			return err
		}
		restored, restoredInfo, restoreErr := readAuthorizedKeys(expectedUID)
		if restoreErr != nil ||
			!bytes.Equal(restored, original) ||
			!authorizedKeysIdentityMatchesOriginal(
				restoredInfo,
				restored,
				*originalMetadata,
				false,
				expectedUID,
				expectedGID,
			) {
			clear(restored)
			return ErrSupervisorRecovery
		}
		clear(restored)
	default:
		return ErrSupervisorRecovery
	}
	return removeRootPrivateExact(PeerAuthorizedKeysWitnessPath, 0o600)
}

func reconcileAuthorizedKeysScratch(
	current []byte,
	info os.FileInfo,
	original *AuthorizedKeysOriginal,
	expectedUID uint32,
	expectedGID uint32,
) error {
	scratchInfo, err := os.Lstat(PeerAuthorizedKeysScratchPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil ||
		original == nil ||
		original.Validate() != nil ||
		!scratchInfo.Mode().IsRegular() ||
		scratchInfo.Mode()&os.ModeSymlink != 0 ||
		scratchInfo.Mode().Perm() != 0o600 {
		return ErrSupervisorRecovery
	}
	scratchStat, ok := scratchInfo.Sys().(*syscall.Stat_t)
	if !ok || scratchStat.Uid != 0 || scratchStat.Nlink != 1 {
		return ErrSupervisorRecovery
	}
	if _, finalErr := os.Lstat(PeerAuthorizedKeysWitnessPath); !errors.Is(
		finalErr,
		os.ErrNotExist,
	) {
		return ErrSupervisorRecovery
	}
	if !authorizedKeysIdentityMatchesOriginal(
		info,
		current,
		*original,
		true,
		expectedUID,
		expectedGID,
	) {
		return ErrSupervisorRecovery
	}
	return removeRootPrivateExact(PeerAuthorizedKeysScratchPath, 0o600)
}

type authorizedKeyRecoveryAction uint8

const (
	authorizedKeyNoChange authorizedKeyRecoveryAction = iota
	authorizedKeyRemoveWitness
	authorizedKeyRestoreAndRemoveWitness
)

func decideAuthorizedKeyRecovery(
	current []byte,
	witness []byte,
	line []byte,
	witnessPresent bool,
	original *AuthorizedKeysOriginal,
) (authorizedKeyRecoveryAction, error) {
	if !ValidAuthorizedKeyLine(string(line)) ||
		original == nil ||
		original.Validate() != nil {
		return authorizedKeyNoChange, ErrSupervisorRecovery
	}
	if !witnessPresent {
		if bytes.Contains(current, line) {
			return authorizedKeyNoChange, ErrSupervisorRecovery
		}
		if !authorizedKeysBytesMatchOriginal(current, *original) {
			return authorizedKeyNoChange, ErrSupervisorRecovery
		}
		return authorizedKeyNoChange, nil
	}
	if !authorizedKeysBytesMatchOriginal(witness, *original) {
		return authorizedKeyNoChange, ErrSupervisorRecovery
	}
	if bytes.Equal(current, witness) {
		return authorizedKeyRemoveWitness, nil
	}
	expected := make([]byte, 0, len(witness)+len(line))
	expected = append(expected, witness...)
	expected = append(expected, line...)
	defer clear(expected)
	if bytes.Equal(current, expected) {
		return authorizedKeyRestoreAndRemoveWitness, nil
	}
	return authorizedKeyNoChange, ErrSupervisorRecovery
}

func authorizedKeysOriginal(
	info os.FileInfo,
	data []byte,
	expectedUID uint32,
	expectedGID uint32,
) (AuthorizedKeysOriginal, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok ||
		!authorizedKeysSafeIdentity(info, expectedUID, expectedGID) ||
		info.Size() != int64(len(data)) {
		return AuthorizedKeysOriginal{}, ErrUnsafeSupervisorFile
	}
	original := AuthorizedKeysOriginal{
		Device: uint64(stat.Dev),
		Inode:  uint64(stat.Ino),
		Size:   uint64(len(data)),
		UID:    stat.Uid,
		GID:    stat.Gid,
		Mode:   uint32(info.Mode().Perm()),
		SHA256: HashHex(data),
	}
	if original.Validate() != nil {
		return AuthorizedKeysOriginal{}, ErrUnsafeSupervisorFile
	}
	return original, nil
}

func authorizedKeysBytesMatchOriginal(
	data []byte,
	original AuthorizedKeysOriginal,
) bool {
	return uint64(len(data)) == original.Size &&
		HashHex(data) == original.SHA256
}

func authorizedKeysSafeIdentity(
	info os.FileInfo,
	expectedUID uint32,
	expectedGID uint32,
) bool {
	if info == nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok &&
		stat.Uid == expectedUID &&
		stat.Gid == expectedGID &&
		stat.Nlink == 1
}

func authorizedKeysIdentityMatchesOriginal(
	info os.FileInfo,
	data []byte,
	original AuthorizedKeysOriginal,
	requireOriginalInode bool,
	expectedUID uint32,
	expectedGID uint32,
) bool {
	if !authorizedKeysSafeIdentity(info, expectedUID, expectedGID) ||
		!authorizedKeysBytesMatchOriginal(data, original) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if requireOriginalInode &&
		(uint64(stat.Dev) != original.Device ||
			uint64(stat.Ino) != original.Inode) {
		return false
	}
	return stat.Uid == original.UID &&
		stat.Gid == original.GID &&
		uint32(info.Mode().Perm()) == original.Mode
}

func proveAuthorizedLineAbsent(line []byte, expectedUID uint32) error {
	current, _, err := readAuthorizedKeys(expectedUID)
	if err != nil {
		return err
	}
	defer clear(current)
	if bytes.Contains(current, line) {
		return ErrSupervisorRecovery
	}
	return nil
}

func readAuthorizedKeys(expectedUID uint32) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(RestrictedAuthorizedKeysPath)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 {
		return nil, nil, ErrUnsafeSupervisorFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID || stat.Nlink != 1 {
		return nil, nil, ErrUnsafeSupervisorFile
	}
	file, err := os.OpenFile(
		RestrictedAuthorizedKeysPath,
		os.O_RDONLY|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, nil, ErrUnsafeSupervisorFile
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, ErrUnsafeSupervisorFile
	}
	data, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		clear(data)
		return nil, nil, ErrUnsafeSupervisorFile
	}
	after, err := file.Stat()
	pathInfo, pathErr := os.Lstat(RestrictedAuthorizedKeysPath)
	if err != nil || pathErr != nil ||
		!os.SameFile(opened, after) ||
		!os.SameFile(opened, pathInfo) ||
		after.Size() != int64(len(data)) {
		clear(data)
		return nil, nil, ErrUnsafeSupervisorFile
	}
	return data, opened, nil
}

func replaceAuthorizedKeys(
	data []byte,
	expected os.FileInfo,
	uid uint32,
	gid uint32,
) error {
	parent := filepath.Dir(RestrictedAuthorizedKeysPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil ||
		!parentInfo.IsDir() ||
		parentInfo.Mode()&os.ModeSymlink != 0 ||
		parentInfo.Mode().Perm() != 0o700 {
		return ErrUnsafeSupervisorFile
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != uid {
		return ErrUnsafeSupervisorFile
	}
	current, err := os.Lstat(RestrictedAuthorizedKeysPath)
	if err != nil || !os.SameFile(expected, current) {
		return ErrSupervisorRecovery
	}
	temporary, err := os.CreateTemp(parent, ".authorized-keys-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chown(int(uid), int(gid)); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	temporaryInfo, err := temporary.Stat()
	if err != nil ||
		!temporaryInfo.Mode().IsRegular() ||
		temporaryInfo.Mode().Perm() != 0o600 ||
		temporaryInfo.Size() != int64(len(data)) {
		_ = temporary.Close()
		return ErrUnsafeSupervisorFile
	}
	temporaryStat, ok := temporaryInfo.Sys().(*syscall.Stat_t)
	if !ok ||
		temporaryStat.Uid != uid ||
		temporaryStat.Gid != gid ||
		temporaryStat.Nlink != 1 {
		_ = temporary.Close()
		return ErrUnsafeSupervisorFile
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	current, err = os.Lstat(RestrictedAuthorizedKeysPath)
	if err != nil || !os.SameFile(expected, current) {
		return ErrSupervisorRecovery
	}
	if err := os.Rename(temporaryPath, RestrictedAuthorizedKeysPath); err != nil {
		return err
	}
	installed, err := os.Lstat(RestrictedAuthorizedKeysPath)
	if err != nil ||
		!os.SameFile(temporaryInfo, installed) ||
		!installed.Mode().IsRegular() ||
		installed.Mode().Perm() != 0o600 ||
		installed.Size() != int64(len(data)) {
		return ErrUnsafeSupervisorFile
	}
	installedStat, ok := installed.Sys().(*syscall.Stat_t)
	if !ok ||
		installedStat.Uid != uid ||
		installedStat.Gid != gid ||
		installedStat.Nlink != 1 {
		return ErrUnsafeSupervisorFile
	}
	return syncParent(parent)
}

func publishRunNonce(nonce []byte) error {
	if len(nonce) != 32 {
		return ErrSupervisorState
	}
	return writeRootPrivateCreateOnly(PeerRunNoncePath, nonce, 0o444)
}

func removeRunNonce() error {
	return removeRootPrivateExact(PeerRunNoncePath, 0o444)
}

func writeRootPrivateCreateOnly(
	path string,
	data []byte,
	mode os.FileMode,
) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeSupervisorFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return ErrUnsafeSupervisorFile
	}
	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,
		mode,
	)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	opened, err := file.Stat()
	closeErr := file.Close()
	if err != nil || closeErr != nil ||
		!opened.Mode().IsRegular() ||
		opened.Mode().Perm() != mode.Perm() ||
		opened.Size() != int64(len(data)) {
		return ErrUnsafeSupervisorFile
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || openedStat.Uid != 0 || openedStat.Nlink != 1 {
		return ErrUnsafeSupervisorFile
	}
	pathInfo, err := os.Lstat(path)
	if err != nil ||
		!os.SameFile(opened, pathInfo) ||
		!pathInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 ||
		pathInfo.Mode().Perm() != mode.Perm() ||
		pathInfo.Size() != int64(len(data)) {
		return ErrUnsafeSupervisorFile
	}
	pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok || pathStat.Uid != 0 || pathStat.Nlink != 1 {
		return ErrUnsafeSupervisorFile
	}
	return syncParent(parent)
}

// writeRootPrivateAtomicCreateOnly keeps an interrupted write at a fixed
// journal-owned scratch path. Recovery may safely remove that unpublished
// scratch only while authorized_keys still matches the durable original
// identity; the published witness is always complete or absent.
func writeRootPrivateAtomicCreateOnly(
	path string,
	scratchPath string,
	data []byte,
	mode os.FileMode,
) error {
	if path == scratchPath ||
		filepath.Dir(path) != filepath.Dir(scratchPath) {
		return ErrUnsafeSupervisorFile
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return os.ErrExist
		}
		return err
	}
	if err := writeRootPrivateCreateOnly(scratchPath, data, mode); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return ErrSupervisorRecovery
	}
	if err := os.Rename(scratchPath, path); err != nil {
		return err
	}
	final, err := readRootPrivateExact(path, len(data), mode)
	if err != nil || !bytes.Equal(final, data) {
		clear(final)
		return ErrSupervisorRecovery
	}
	clear(final)
	return syncParent(filepath.Dir(path))
}

func readRootPrivateExact(
	path string,
	maximum int,
	mode os.FileMode,
) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != mode.Perm() {
		return nil, ErrUnsafeSupervisorFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return nil, ErrUnsafeSupervisorFile
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsafeSupervisorFile
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum+1)))
	if err != nil || len(data) > maximum || int64(len(data)) != info.Size() {
		clear(data)
		return nil, ErrUnsafeSupervisorFile
	}
	return data, nil
}

func removeRootPrivateExact(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != mode.Perm() {
		return ErrUnsafeSupervisorFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return ErrUnsafeSupervisorFile
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncParent(filepath.Dir(path))
}

func clearPeerChildReady(ready *PeerChildReady) {
	if ready == nil {
		return
	}
	clearPeerArtifacts(&ready.Artifacts)
	clear(ready.RunNonce)
	*ready = PeerChildReady{}
}
