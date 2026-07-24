//go:build darwin && kyclash_utun && (kyclash_vm_network_lab || kyclash_vm_external_peer_lab)

package vmnetworklab

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
)

// RecoverJournal reconciles one exact retained journal before Mihomo is
// started or the App socket is opened. Any unprovable ownership leaves the
// record intact and refuses the new session.
func RecoverJournal(
	ctx context.Context,
	store JournalStore,
	record JournalRecord,
	inspector RouteInspector,
	executor RouteExecutor,
	baseline SystemSnapshot,
) error {
	return RecoverJournalWithMihomoContract(ctx, store, record, inspector, executor, baseline, DefaultMihomoContract())
}

// RecoverJournalWithMihomoContract reconciles one retained record for an
// explicitly compiled lab composition. It keeps the legacy wrapper above
// source-compatible while allowing the external-peer lab to use a disjoint,
// fixed filesystem root.
func RecoverJournalWithMihomoContract(
	ctx context.Context,
	store JournalStore,
	record JournalRecord,
	inspector RouteInspector,
	executor RouteExecutor,
	baseline SystemSnapshot,
	contract MihomoContract,
) error {
	if !contract.valid() {
		return ErrMihomoIdentity
	}
	if err := record.Validate(); err != nil {
		return err
	}
	snapshot, err := inspector.Snapshot()
	if err != nil {
		return err
	}
	if exact, exists := hasExactRoute(snapshot.all(), PrivatePrefix()); exists {
		if !validUTUN(record.TunnelInterface) || exact.Interface != record.TunnelInterface {
			return ErrRouteAmbiguous
		}
		record.State = StateDeletePending
		if err := store.Save(record); err != nil {
			return err
		}
		if err := executor.Delete(record.TunnelInterface); err != nil {
			return errors.Join(ErrRouteAmbiguous, err)
		}
		snapshot, err = inspector.Snapshot()
		if err != nil {
			return err
		}
		if _, exists := hasExactRoute(snapshot.all(), PrivatePrefix()); exists {
			return ErrRouteAmbiguous
		}
	}
	if record.TunnelInterface != "" {
		if _, err := net.InterfaceByName(record.TunnelInterface); err == nil {
			// The journal cannot recreate the lost wireguard-go device handle;
			// retaining the record is safer than claiming an arbitrary utun.
			return errors.New("journaled KyClash utun remains without its owner handle")
		}
	}
	record.State = StateTeardown
	if record.TunnelInterface == "" {
		record.State = StateStartPending
	}
	if err := store.Save(record); err != nil {
		return err
	}
	if record.MihomoChild.PID > 1 {
		processState := syscall.Kill(record.MihomoChild.PID, 0)
		if processState == nil || errors.Is(processState, syscall.EPERM) {
			manager := NewMihomoManagerWithContract(inspector, contract)
			if err := manager.AdoptForRecovery(record.MihomoChild); err != nil {
				return err
			}
			if err := manager.Stop(ctx); err != nil {
				return err
			}
		} else if !errors.Is(processState, syscall.ESRCH) {
			return ErrMihomoIdentity
		}
	}
	if info, err := os.Lstat(contract.SocketPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || !isRootOwned(info) {
			return ErrMihomoIdentity
		}
		if processExistsAtPath(contract.Executable) {
			return ErrMihomoIdentity
		}
		if err := os.Remove(contract.SocketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := VerifyFinalAbsenceWithMihomoContract(inspector, baseline, record.TunnelInterface, contract); err != nil {
		return err
	}
	record.State = StateReleased
	if err := store.Save(record); err != nil {
		return err
	}
	return store.Remove()
}
