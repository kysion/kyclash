package externalpeer

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ErrSupervisorState    = errors.New("invalid external-peer supervisor state")
	ErrSupervisorRecovery = errors.New("external-peer supervisor recovery required")
)

type SupervisorRun struct {
	RunID                  string
	TicketHash             string
	ExpiresAt              time.Time
	AuthorizedKeyLine      string
	AuthorizedKeysOriginal *AuthorizedKeysOriginal
}

type SupervisorOperations interface {
	ValidateStaging(context.Context) error
	ObserveAuthorizedKey(context.Context, SupervisorRun) (AuthorizedKeysOriginal, error)
	PrepareAuthorizedKey(context.Context, SupervisorRun) error
	InstallAuthorizedKey(context.Context, SupervisorRun) error
	StartPeerChild(
		context.Context,
		SupervisorRun,
		func(ChildIdentity) error,
	) (ChildIdentity, error)
	StopPeerChild(context.Context, ChildIdentity) error
	RemoveAuthorizedKey(context.Context, SupervisorRun) error
	RemoveRunArtifacts(context.Context, SupervisorRun) error
	ProveRunAbsent(context.Context, SupervisorRun, *ChildIdentity) error
}

type PeerSupervisor struct {
	mu    sync.Mutex
	store SupervisorJournalStore
	ops   SupervisorOperations
	state SupervisorState
	run   *SupervisorRun
	child *ChildIdentity
}

func NewPeerSupervisor(
	store SupervisorJournalStore,
	operations SupervisorOperations,
) (*PeerSupervisor, error) {
	if store.Path() == "" || operations == nil {
		return nil, ErrSupervisorState
	}
	return &PeerSupervisor{
		store: store,
		ops:   operations,
		state: SupervisorRecoveryOnly,
	}, nil
}

func (supervisor *PeerSupervisor) State() SupervisorState {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	return supervisor.state
}

func (supervisor *PeerSupervisor) Boot(ctx context.Context) error {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if supervisor.state != SupervisorRecoveryOnly || supervisor.run != nil {
		return ErrSupervisorState
	}
	if err := supervisor.ops.ValidateStaging(ctx); err != nil {
		return err
	}
	journal, exists, err := supervisor.store.Load()
	if err != nil {
		return err
	}
	if !exists {
		supervisor.state = SupervisorIdleReady
		return nil
	}
	run := SupervisorRun{
		RunID:             journal.RunID,
		TicketHash:        journal.TicketHash,
		ExpiresAt:         time.Unix(journal.ExpiresAt, 0),
		AuthorizedKeyLine: journal.AuthorizedKeyLine,
		AuthorizedKeysOriginal: cloneAuthorizedKeysOriginal(
			journal.AuthorizedKeysOriginal,
		),
	}
	supervisor.run = &run
	supervisor.child = journal.Child
	if err := supervisor.cleanupLocked(ctx); err != nil {
		supervisor.state = SupervisorRecoveryOnly
		return ErrSupervisorRecovery
	}
	supervisor.state = SupervisorIdleReady
	return nil
}

func (supervisor *PeerSupervisor) Start(
	ctx context.Context,
	run SupervisorRun,
) (ChildIdentity, error) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if supervisor.state != SupervisorIdleReady ||
		supervisor.run != nil ||
		!validSupervisorRun(run, time.Now().UTC()) {
		return ChildIdentity{}, ErrSupervisorState
	}
	original, err := supervisor.ops.ObserveAuthorizedKey(ctx, run)
	if err != nil {
		return ChildIdentity{}, err
	}
	if original.Validate() != nil ||
		!validSupervisorRun(run, time.Now().UTC()) {
		return ChildIdentity{}, ErrSupervisorState
	}
	run.AuthorizedKeysOriginal = &original
	supervisor.run = &run
	supervisor.state = SupervisorAccepted
	if err := supervisor.saveLocked(SupervisorAccepted, nil); err != nil {
		supervisor.run = nil
		supervisor.state = SupervisorRecoveryOnly
		return ChildIdentity{}, err
	}
	if err := supervisor.ops.PrepareAuthorizedKey(ctx, run); err != nil {
		_ = supervisor.cleanupLocked(ctx)
		return ChildIdentity{}, err
	}
	if err := supervisor.ops.InstallAuthorizedKey(ctx, run); err != nil {
		_ = supervisor.cleanupLocked(ctx)
		return ChildIdentity{}, err
	}
	supervisor.state = SupervisorChildStarting
	if err := supervisor.saveLocked(SupervisorChildStarting, nil); err != nil {
		_ = supervisor.cleanupLocked(ctx)
		return ChildIdentity{}, err
	}
	child, err := supervisor.ops.StartPeerChild(
		ctx,
		run,
		func(identity ChildIdentity) error {
			if identity.Validate(run.RunID) != nil {
				return ErrSupervisorState
			}
			supervisor.child = &identity
			return supervisor.saveLocked(
				SupervisorChildStarting,
				supervisor.child,
			)
		},
	)
	if err != nil ||
		child.Validate(run.RunID) != nil ||
		supervisor.child == nil ||
		*supervisor.child != child {
		_ = supervisor.cleanupLocked(ctx)
		if err != nil {
			return ChildIdentity{}, err
		}
		return ChildIdentity{}, ErrSupervisorState
	}
	supervisor.child = &child
	supervisor.state = SupervisorRunning
	if err := supervisor.saveLocked(SupervisorRunning, &child); err != nil {
		_ = supervisor.cleanupLocked(ctx)
		return ChildIdentity{}, err
	}
	return child, nil
}

func (supervisor *PeerSupervisor) Stop(ctx context.Context) error {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if supervisor.run == nil {
		if supervisor.state == SupervisorIdleReady ||
			supervisor.state == SupervisorCleanPostflight {
			return nil
		}
		return ErrSupervisorState
	}
	return supervisor.cleanupLocked(ctx)
}

func (supervisor *PeerSupervisor) cleanupLocked(ctx context.Context) error {
	run := supervisor.run
	if run == nil {
		return ErrSupervisorState
	}
	supervisor.state = SupervisorCleaning
	if err := supervisor.saveLocked(SupervisorCleaning, supervisor.child); err != nil {
		supervisor.state = SupervisorRecoveryOnly
		return err
	}
	var cleanupErr error
	if supervisor.child != nil {
		cleanupErr = errors.Join(
			cleanupErr,
			supervisor.ops.StopPeerChild(ctx, *supervisor.child),
		)
	}
	cleanupErr = errors.Join(
		cleanupErr,
		supervisor.ops.RemoveAuthorizedKey(ctx, *run),
		supervisor.ops.RemoveRunArtifacts(ctx, *run),
		supervisor.ops.ProveRunAbsent(ctx, *run, supervisor.child),
	)
	if cleanupErr != nil {
		supervisor.state = SupervisorRecoveryOnly
		_ = supervisor.saveLocked(SupervisorRecoveryOnly, supervisor.child)
		return cleanupErr
	}
	if err := supervisor.store.Remove(); err != nil {
		supervisor.state = SupervisorRecoveryOnly
		return err
	}
	supervisor.run = nil
	supervisor.child = nil
	supervisor.state = SupervisorCleanPostflight
	return nil
}

func (supervisor *PeerSupervisor) saveLocked(
	state SupervisorState,
	child *ChildIdentity,
) error {
	if supervisor.run == nil {
		return ErrSupervisorState
	}
	return supervisor.store.Save(SupervisorJournal{
		SchemaVersion:           SchemaVersion,
		State:                   state,
		RunID:                   supervisor.run.RunID,
		TicketHash:              supervisor.run.TicketHash,
		ExpiresAt:               supervisor.run.ExpiresAt.Unix(),
		AuthorizedKeyLine:       supervisor.run.AuthorizedKeyLine,
		AuthorizedKeyLineSHA256: HashHex([]byte(supervisor.run.AuthorizedKeyLine)),
		AuthorizedKeysOriginal: cloneAuthorizedKeysOriginal(
			supervisor.run.AuthorizedKeysOriginal,
		),
		Child: child,
	})
}

func cloneAuthorizedKeysOriginal(
	original *AuthorizedKeysOriginal,
) *AuthorizedKeysOriginal {
	if original == nil {
		return nil
	}
	value := *original
	return &value
}

func validSupervisorRun(run SupervisorRun, now time.Time) bool {
	return validRunID(run.RunID) &&
		validSHA256(run.TicketHash) &&
		run.ExpiresAt.After(now) &&
		!run.ExpiresAt.After(now.Add(MaxRunLifetime)) &&
		run.AuthorizedKeysOriginal == nil &&
		ValidAuthorizedKeyLine(run.AuthorizedKeyLine)
}

func ValidAuthorizedKeyLine(value string) bool {
	const prefix = `from="127.0.0.1",restrict,command="`
	if !(len(value) > len(prefix)+len(ForcedCommandHelperPath)+len(`" ssh-ed25519 `) &&
		value[:len(prefix)] == prefix &&
		len(value) > len(prefix)+len(ForcedCommandHelperPath) &&
		value[len(prefix):len(prefix)+len(ForcedCommandHelperPath)] == ForcedCommandHelperPath &&
		value[len(prefix)+len(ForcedCommandHelperPath):len(prefix)+len(ForcedCommandHelperPath)+len(`" ssh-ed25519 `)] == `" ssh-ed25519 ` &&
		value[len(value)-1] == '\n' &&
		!containsControlExceptNewline(value)) {
		return false
	}
	key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(value))
	return err == nil &&
		key != nil &&
		key.Type() == ssh.KeyAlgoED25519 &&
		comment == "" &&
		len(rest) == 0 &&
		len(options) == 3 &&
		options[0] == `from="127.0.0.1"` &&
		options[1] == "restrict" &&
		options[2] == `command="`+ForcedCommandHelperPath+`"`
}

func containsControlExceptNewline(value string) bool {
	for index, character := range value {
		if character < 0x20 && !(character == '\n' && index == len(value)-1) ||
			character == 0x7f {
			return true
		}
	}
	return false
}
