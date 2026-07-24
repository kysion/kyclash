package externalpeer

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

type PeerSupervisorStatus struct {
	SchemaVersion uint8  `json:"schema_version"`
	State         string `json:"state"`
	RunID         string `json:"run_id,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
}

func RunPeerRootSupervisor(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if runtime.GOOS != "darwin" ||
		runtime.GOARCH != "arm64" ||
		os.Geteuid() != 0 {
		return ErrSupervisorState
	}
	executable, err := os.Executable()
	if err != nil {
		return ErrSupervisorState
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil || resolved != PeerSupervisorPath {
		return ErrSupervisorState
	}
	staging, err := LoadAndValidatePeerStagingManifest()
	if err != nil {
		return err
	}
	fixedConfig, err := LoadPeerSupervisorConfig(staging)
	if err != nil {
		return err
	}
	// Recovery is bound only to immutable guest identity. Mutable en0 and
	// system-sshd drift must never prevent retained child/key cleanup.
	if err := ValidateCurrentPeerRecoveryRuntime(fixedConfig); err != nil {
		return err
	}
	ticketExpectation, err := LoadRunTicketExpectation(staging)
	if err != nil {
		return err
	}
	listenerBaseline, err := LoadPeerListenerBaseline(staging, fixedConfig)
	if err != nil {
		return err
	}
	var inbox *StableDirectory
	if _, statErr := os.Lstat(PeerCourierInbox); statErr == nil {
		inbox, err = OpenStableDirectory(
			PeerCourierInbox,
			fixedConfig.ConsoleUID,
			0o700,
		)
		if err != nil {
			return err
		}
		defer inbox.Close()
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	outbox, err := OpenStableDirectory(PeerPublicOutbox, 0, 0o711)
	if err != nil {
		return err
	}
	defer outbox.Close()
	defer removePeerPublicStatus()

	store := NewSupervisorJournalStore(PeerJournalPath, true)
	if _, exists, err := store.Load(); err != nil {
		return err
	} else if exists {
		if err := publishPeerStatus("recovery-only", "", ""); err != nil {
			return err
		}
		operations, err := NewOSRecoveryOperations(
			staging,
			fixedConfig,
			inbox,
			outbox,
		)
		if err != nil {
			return err
		}
		supervisor, err := NewPeerSupervisor(store, operations)
		if err != nil {
			return err
		}
		if err := supervisor.Boot(ctx); err != nil {
			return err
		}
	}
	// New work is allowed only after recovery has converged and every mutable
	// runtime identity fact matches the fixed peer configuration.
	if err := ValidateCurrentPeerRuntime(fixedConfig); err != nil {
		_ = publishPeerStatus("recovery-only", "", "peer_identity_drift")
		return err
	}
	if err := validateDaemonDirectories(fixedConfig); err != nil ||
		inbox == nil {
		return ErrUnsafeSupervisorFile
	}
	if err := AuditListenerBaseline(ctx, listenerBaseline); err != nil {
		_ = publishPeerStatus("recovery-only", "", "listener_drift")
		return err
	}
	if err := requireEmptyStableDirectory(outbox); err != nil {
		return err
	}
	if err := requireEmptyOrWaitingInbox(inbox); err != nil {
		return err
	}
	if err := publishPeerStatus("idle-ready", "", ""); err != nil {
		return err
	}
	if err := waitForWake(ctx, listenerBaseline); err != nil {
		return err
	}
	validated, err := LoadValidatedPeerRun(
		inbox,
		staging,
		fixedConfig,
		ticketExpectation,
		time.Now().UTC(),
	)
	if err != nil {
		_ = publishPeerStatus("recovery-only", "", "courier_refused")
		return err
	}
	defer validated.Clear()
	operations, err := NewOSPerRunOperations(
		staging,
		fixedConfig,
		validated,
		inbox,
		outbox,
	)
	if err != nil {
		return err
	}
	supervisor, err := NewPeerSupervisor(store, operations)
	if err != nil {
		return err
	}
	if err := supervisor.Boot(ctx); err != nil {
		return err
	}
	if err := publishPeerStatus("starting", validated.Run.RunID, ""); err != nil {
		return err
	}
	if err := ValidateCurrentPeerRuntime(fixedConfig); err != nil {
		_ = publishPeerStatus(
			"recovery-only",
			validated.Run.RunID,
			"peer_identity_drift",
		)
		return err
	}
	if _, err := supervisor.Start(ctx, validated.Run); err != nil {
		_ = publishPeerStatus("recovery-only", validated.Run.RunID, "child_start_failed")
		return err
	}
	if err := operations.ValidateRuntimeListeners(ctx, listenerBaseline); err != nil {
		_ = supervisor.Stop(context.Background())
		_ = publishPeerStatus("recovery-only", validated.Run.RunID, "listener_drift")
		return err
	}
	if err := publishPeerStatus("running", validated.Run.RunID, ""); err != nil {
		_ = supervisor.Stop(context.Background())
		return err
	}
	runErr := monitorPeerRun(
		ctx,
		validated,
		operations,
		listenerBaseline,
	)
	cleanupContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cleanupErr := supervisor.Stop(cleanupContext)
	if cleanupErr != nil {
		_ = publishPeerStatus("recovery-only", validated.Run.RunID, "cleanup_failed")
		return errors.Join(runErr, cleanupErr)
	}
	postflightErr := AuditListenerBaseline(cleanupContext, listenerBaseline)
	if postflightErr != nil {
		_ = publishPeerStatus("recovery-only", validated.Run.RunID, "listener_drift")
		return errors.Join(runErr, postflightErr)
	}
	if errors.Is(runErr, context.Canceled) {
		runErr = nil
	}
	errorCode := ""
	if runErr != nil {
		errorCode = "run_failed"
		if errors.Is(runErr, ErrListenerAudit) {
			errorCode = "listener_drift"
		}
	}
	if err := publishPeerStatus(
		"clean-postflight",
		validated.Run.RunID,
		errorCode,
	); err != nil {
		return errors.Join(runErr, err)
	}
	timer := time.NewTimer(500 * time.Millisecond)
	select {
	case <-ctx.Done():
		timer.Stop()
	case <-timer.C:
	}
	return runErr
}

func monitorPeerRun(
	ctx context.Context,
	validated *ValidatedPeerRun,
	operations *OSPerRunOperations,
	listenerBaseline PeerListenerBaseline,
) error {
	expiry := time.NewTimer(time.Until(validated.Run.ExpiresAt))
	defer expiry.Stop()
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	audit := time.NewTicker(time.Second)
	defer audit.Stop()
	childDone := operations.ProcessDone()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-childDone:
			if !ok || err == nil {
				return ErrPeerChildClosed
			}
			return errors.Join(ErrPeerChildClosed, err)
		case <-expiry.C:
			return context.DeadlineExceeded
		case <-audit.C:
			if err := operations.ValidateRuntimeListeners(
				ctx,
				listenerBaseline,
			); err != nil {
				return ErrListenerAudit
			}
		case <-poll.C:
			if _, err := os.Lstat(PeerCancelTrigger); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
			return validateSignedCancellation(validated, time.Now().UTC())
		}
	}
}

func validateSignedCancellation(
	validated *ValidatedPeerRun,
	now time.Time,
) error {
	if validated == nil || validated.CourierVerifier == nil {
		return ErrSupervisorState
	}
	inbox, err := OpenStableDirectory(
		PeerCourierInbox,
		validated.ConsoleUID,
		0o700,
	)
	if err != nil {
		return err
	}
	defer inbox.Close()
	withCancel := append(
		append([]string(nil), PeerInboxRunNames[:]...),
		"cancel-envelope.bin",
		"cancel-wake",
	)
	if err := inbox.RequireExactNames(withCancel); err != nil {
		return err
	}
	wake, err := inbox.ReadCreateOnlyFile("cancel-wake", 1, 0o600)
	if err != nil || len(wake) != 0 {
		clear(wake)
		return ErrSupervisorState
	}
	clear(wake)
	envelope, err := inbox.ReadCreateOnlyFile(
		"cancel-envelope.bin",
		MaxChildControlFrame,
		0o600,
	)
	if err != nil {
		return err
	}
	defer clear(envelope)
	_, err = validated.CourierVerifier.Accept(envelope, CourierExpectation{
		Kind:        CourierCancel,
		Sequence:    3,
		RunID:       validated.Run.RunID,
		Now:         now,
		Source:      validated.ClientFacts,
		Destination: validated.PeerFacts,
		TicketHash:  validated.TicketHash,
	})
	return err
}

func validateDaemonDirectories(config PeerSupervisorConfig) error {
	expected := []struct {
		path string
		uid  uint32
		mode os.FileMode
	}{
		{RootStateDir, 0, 0o711},
		{PeerCourierInbox, config.ConsoleUID, 0o700},
		{PeerPublicOutbox, 0, 0o711},
		{filepath.Dir(PeerJournalPath), 0, 0o700},
		{filepath.Dir(PeerRunNoncePath), 0, 0o755},
	}
	for _, value := range expected {
		info, err := os.Lstat(value.path)
		if err != nil ||
			!info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != value.mode {
			return ErrUnsafeSupervisorFile
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != value.uid {
			return ErrUnsafeSupervisorFile
		}
	}
	return nil
}

func requireEmptyStableDirectory(directory *StableDirectory) error {
	return directory.RequireExactNames(nil)
}

func requireEmptyOrWaitingInbox(directory *StableDirectory) error {
	if err := directory.RequireExactNames(nil); err == nil {
		return nil
	}
	return directory.RequireExactNames(PeerInboxRunNames[:])
}

func waitForWake(
	ctx context.Context,
	listenerBaseline PeerListenerBaseline,
) error {
	triggerPoll := time.NewTicker(100 * time.Millisecond)
	defer triggerPoll.Stop()
	audit := time.NewTicker(time.Second)
	defer audit.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-audit.C:
			if err := AuditListenerBaseline(ctx, listenerBaseline); err != nil {
				return err
			}
		case <-triggerPoll.C:
			info, err := os.Lstat(PeerWakeTrigger)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil ||
				!info.Mode().IsRegular() ||
				info.Mode()&os.ModeSymlink != 0 ||
				info.Mode().Perm() != 0o600 ||
				info.Size() != 0 {
				return ErrUnsafeSupervisorFile
			}
			return nil
		}
	}
}

func publishPeerStatus(state, runID, errorCode string) error {
	value := PeerSupervisorStatus{
		SchemaVersion: SchemaVersion,
		State:         state,
		RunID:         runID,
		ErrorCode:     errorCode,
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 1024 {
		return ErrSupervisorState
	}
	encoded = append(encoded, '\n')
	defer clear(encoded)
	parent := filepath.Dir(PeerPublicStatus)
	temporary, err := os.CreateTemp(parent, ".peer-status-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if current, err := os.Lstat(PeerPublicStatus); err == nil {
		stat, ok := current.Sys().(*syscall.Stat_t)
		if !ok ||
			stat.Uid != 0 ||
			stat.Nlink != 1 ||
			!current.Mode().IsRegular() ||
			current.Mode()&os.ModeSymlink != 0 ||
			current.Mode().Perm() != 0o644 {
			return ErrUnsafeSupervisorFile
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporaryPath, PeerPublicStatus); err != nil {
		return err
	}
	return syncParent(parent)
}

func removePeerPublicStatus() error {
	return removeRootPrivateExact(PeerPublicStatus, 0o644)
}
