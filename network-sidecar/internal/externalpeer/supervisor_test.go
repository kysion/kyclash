package externalpeer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type fakeSupervisorOperations struct {
	validateCount        int
	observeKeyCount      int
	prepareKeyCount      int
	installCount         int
	startCount           int
	stopCount            int
	removeKeyCount       int
	removeArtifactsCount int
	proveCount           int
	stopErr              error
	child                ChildIdentity
}

func (operations *fakeSupervisorOperations) ValidateStaging(context.Context) error {
	operations.validateCount++
	return nil
}
func (operations *fakeSupervisorOperations) InstallAuthorizedKey(context.Context, SupervisorRun) error {
	operations.installCount++
	return nil
}
func (operations *fakeSupervisorOperations) ObserveAuthorizedKey(
	context.Context,
	SupervisorRun,
) (AuthorizedKeysOriginal, error) {
	operations.observeKeyCount++
	return testAuthorizedKeysOriginal(), nil
}
func (operations *fakeSupervisorOperations) PrepareAuthorizedKey(
	context.Context,
	SupervisorRun,
) error {
	operations.prepareKeyCount++
	return nil
}
func (operations *fakeSupervisorOperations) StartPeerChild(
	_ context.Context,
	_ SupervisorRun,
	onBound func(ChildIdentity) error,
) (ChildIdentity, error) {
	operations.startCount++
	if err := onBound(operations.child); err != nil {
		return ChildIdentity{}, err
	}
	return operations.child, nil
}
func (operations *fakeSupervisorOperations) StopPeerChild(context.Context, ChildIdentity) error {
	operations.stopCount++
	return operations.stopErr
}
func (operations *fakeSupervisorOperations) RemoveAuthorizedKey(context.Context, SupervisorRun) error {
	operations.removeKeyCount++
	return nil
}
func (operations *fakeSupervisorOperations) RemoveRunArtifacts(context.Context, SupervisorRun) error {
	operations.removeArtifactsCount++
	return nil
}
func (operations *fakeSupervisorOperations) ProveRunAbsent(context.Context, SupervisorRun, *ChildIdentity) error {
	operations.proveCount++
	return nil
}

func TestSupervisorJournalsChildAndReachesCleanPostflight(t *testing.T) {
	store := newTestSupervisorStore(t)
	run := testSupervisorRun(t)
	operations := &fakeSupervisorOperations{
		child: testChildIdentity(run.RunID),
	}
	supervisor, err := NewPeerSupervisor(store, operations)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Boot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if supervisor.State() != SupervisorIdleReady {
		t.Fatalf("unexpected boot state: %s", supervisor.State())
	}
	child, err := supervisor.Start(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if child.RunID != run.RunID || supervisor.State() != SupervisorRunning {
		t.Fatalf("unexpected child/state: %#v %s", child, supervisor.State())
	}
	journal, exists, err := store.Load()
	if err != nil || !exists {
		t.Fatalf("journal missing: %v", err)
	}
	if journal.State != SupervisorRunning ||
		journal.Child == nil ||
		journal.Child.PID != child.PID ||
		journal.AuthorizedKeyLine != run.AuthorizedKeyLine {
		t.Fatalf("unexpected journal: %#v", journal)
	}
	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if supervisor.State() != SupervisorCleanPostflight {
		t.Fatalf("unexpected final state: %s", supervisor.State())
	}
	if _, exists, err := store.Load(); err != nil || exists {
		t.Fatalf("journal remained: exists=%v err=%v", exists, err)
	}
	if operations.observeKeyCount != 1 ||
		operations.prepareKeyCount != 1 ||
		operations.installCount != 1 ||
		operations.startCount != 1 ||
		operations.stopCount != 1 ||
		operations.removeKeyCount != 1 ||
		operations.removeArtifactsCount != 1 ||
		operations.proveCount != 1 {
		t.Fatalf("unexpected operations: %#v", operations)
	}
}

func TestSupervisorFailedCleanupRequiresNextBootRecovery(t *testing.T) {
	store := newTestSupervisorStore(t)
	run := testSupervisorRun(t)
	firstOps := &fakeSupervisorOperations{
		child:   testChildIdentity(run.RunID),
		stopErr: errors.New("injected stop ambiguity"),
	}
	first, err := NewPeerSupervisor(store, firstOps)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Boot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Start(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if err := first.Stop(context.Background()); err == nil {
		t.Fatal("ambiguous cleanup was accepted")
	}
	if first.State() != SupervisorRecoveryOnly {
		t.Fatalf("unexpected failure state: %s", first.State())
	}
	journal, exists, err := store.Load()
	if err != nil || !exists || journal.State != SupervisorRecoveryOnly {
		t.Fatalf("recovery journal missing: %#v %v", journal, err)
	}

	recoveryOps := &fakeSupervisorOperations{
		child: testChildIdentity(run.RunID),
	}
	restarted, err := NewPeerSupervisor(store, recoveryOps)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Boot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restarted.State() != SupervisorIdleReady {
		t.Fatalf("recovery did not reach idle: %s", restarted.State())
	}
	if recoveryOps.stopCount != 1 ||
		recoveryOps.removeKeyCount != 1 ||
		recoveryOps.proveCount != 1 {
		t.Fatalf("recovery did not reconcile exact run: %#v", recoveryOps)
	}
}

func TestSupervisorPersistsKeyAndChildCrashBoundariesBeforeUse(t *testing.T) {
	store := newTestSupervisorStore(t)
	run := testSupervisorRun(t)
	child := testChildIdentity(run.RunID)
	operations := &journalObservingOperations{
		t: t, store: store, child: child,
	}
	supervisor, err := NewPeerSupervisor(store, operations)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Boot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.Start(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if !operations.observed ||
		!operations.preparedObserved ||
		!operations.installedObserved ||
		!operations.childBoundObserved {
		t.Fatalf("journal boundaries were skipped: %#v", operations)
	}
}

type journalObservingOperations struct {
	t                  *testing.T
	store              SupervisorJournalStore
	child              ChildIdentity
	observed           bool
	preparedObserved   bool
	installedObserved  bool
	childBoundObserved bool
}

func (operations *journalObservingOperations) ValidateStaging(context.Context) error {
	return nil
}

func (operations *journalObservingOperations) ObserveAuthorizedKey(
	context.Context,
	SupervisorRun,
) (AuthorizedKeysOriginal, error) {
	if _, exists, err := operations.store.Load(); err != nil || exists {
		operations.t.Fatalf(
			"observe must precede every journal/mutation: exists=%v err=%v",
			exists,
			err,
		)
	}
	operations.observed = true
	return testAuthorizedKeysOriginal(), nil
}

func (operations *journalObservingOperations) PrepareAuthorizedKey(
	_ context.Context,
	run SupervisorRun,
) error {
	journal := operations.requireJournal(SupervisorAccepted)
	if journal.AuthorizedKeysOriginal == nil ||
		run.AuthorizedKeysOriginal == nil ||
		*journal.AuthorizedKeysOriginal != *run.AuthorizedKeysOriginal ||
		journal.Child != nil {
		operations.t.Fatal("original authorized_keys identity was not durable before witness")
	}
	operations.preparedObserved = true
	return nil
}

func (operations *journalObservingOperations) InstallAuthorizedKey(
	_ context.Context,
	run SupervisorRun,
) error {
	journal := operations.requireJournal(SupervisorAccepted)
	if journal.AuthorizedKeysOriginal == nil ||
		run.AuthorizedKeysOriginal == nil ||
		*journal.AuthorizedKeysOriginal != *run.AuthorizedKeysOriginal ||
		journal.Child != nil {
		operations.t.Fatal("original authorized_keys identity was not durable before install")
	}
	operations.installedObserved = true
	return nil
}

func (operations *journalObservingOperations) StartPeerChild(
	_ context.Context,
	_ SupervisorRun,
	onBound func(ChildIdentity) error,
) (ChildIdentity, error) {
	journal := operations.requireJournal(SupervisorChildStarting)
	if journal.AuthorizedKeysOriginal == nil || journal.Child != nil {
		operations.t.Fatal("child-starting journal was invalid before spawn")
	}
	if err := onBound(operations.child); err != nil {
		return ChildIdentity{}, err
	}
	journal = operations.requireJournal(SupervisorChildStarting)
	if journal.Child == nil || *journal.Child != operations.child {
		operations.t.Fatal("bound child identity was not durable before bootstrap")
	}
	operations.childBoundObserved = true
	return operations.child, nil
}

func (*journalObservingOperations) StopPeerChild(context.Context, ChildIdentity) error {
	return nil
}

func (*journalObservingOperations) RemoveAuthorizedKey(context.Context, SupervisorRun) error {
	return nil
}

func (*journalObservingOperations) RemoveRunArtifacts(context.Context, SupervisorRun) error {
	return nil
}

func (*journalObservingOperations) ProveRunAbsent(
	context.Context,
	SupervisorRun,
	*ChildIdentity,
) error {
	return nil
}

func (operations *journalObservingOperations) requireJournal(
	state SupervisorState,
) SupervisorJournal {
	operations.t.Helper()
	journal, exists, err := operations.store.Load()
	if err != nil || !exists || journal.State != state {
		operations.t.Fatalf(
			"unexpected journal at %s: exists=%v journal=%#v err=%v",
			state,
			exists,
			journal,
			err,
		)
	}
	return journal
}

func TestSupervisorBootRecoversEveryDurableCrashStateWithoutFreshExpiry(t *testing.T) {
	run := testSupervisorRun(t)
	run.ExpiresAt = time.Unix(1, 0)
	original := testAuthorizedKeysOriginal()
	child := testChildIdentity(run.RunID)
	tests := []struct {
		name     string
		state    SupervisorState
		original *AuthorizedKeysOriginal
		child    *ChildIdentity
		wantStop int
	}{
		{
			name: "accepted-before-witness", state: SupervisorAccepted,
			original: &original,
		},
		{
			name: "accepted-after-witness", state: SupervisorAccepted,
			original: &original,
		},
		{
			name: "child-starting-before-spawn", state: SupervisorChildStarting,
			original: &original,
		},
		{
			name: "child-starting-after-bind", state: SupervisorChildStarting,
			original: &original, child: &child, wantStop: 1,
		},
		{
			name: "running", state: SupervisorRunning,
			original: &original, child: &child, wantStop: 1,
		},
		{
			name: "cleaning", state: SupervisorCleaning,
			original: &original, child: &child, wantStop: 1,
		},
		{
			name: "recovery-only", state: SupervisorRecoveryOnly,
			original: &original, child: &child, wantStop: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newTestSupervisorStore(t)
			journal := SupervisorJournal{
				SchemaVersion:           SchemaVersion,
				State:                   test.state,
				RunID:                   run.RunID,
				TicketHash:              run.TicketHash,
				ExpiresAt:               run.ExpiresAt.Unix(),
				AuthorizedKeyLine:       run.AuthorizedKeyLine,
				AuthorizedKeyLineSHA256: HashHex([]byte(run.AuthorizedKeyLine)),
				AuthorizedKeysOriginal:  cloneAuthorizedKeysOriginal(test.original),
				Child:                   test.child,
			}
			if err := store.Save(journal); err != nil {
				t.Fatal(err)
			}
			operations := &fakeSupervisorOperations{child: child}
			supervisor, err := NewPeerSupervisor(store, operations)
			if err != nil {
				t.Fatal(err)
			}
			if err := supervisor.Boot(context.Background()); err != nil {
				t.Fatal(err)
			}
			if supervisor.State() != SupervisorIdleReady ||
				operations.stopCount != test.wantStop ||
				operations.removeKeyCount != 1 ||
				operations.removeArtifactsCount != 1 ||
				operations.proveCount != 1 {
				t.Fatalf("crash state did not converge: %#v", operations)
			}
			if _, exists, err := store.Load(); err != nil || exists {
				t.Fatalf("journal remained after recovery: exists=%v err=%v", exists, err)
			}
		})
	}
}

func TestRecoveryOperationsDoNotRequireCourierInbox(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	staged := func(path string, mode uint32, salt string) StagedFile {
		return StagedFile{
			Path:   path,
			SHA256: HashHex([]byte(salt)),
			UID:    0,
			Mode:   mode,
			Device: 1,
			Inode:  2,
			Size:   1,
		}
	}
	manifest := PeerStagingManifest{
		SchemaVersion:        SchemaVersion,
		PeerSupervisor:       staged(PeerSupervisorPath, 0o755, "supervisor"),
		PeerChild:            staged(PeerChildPath, 0o755, "child"),
		PeerConfig:           staged(PeerFixedConfigPath, 0o600, "config"),
		RunTicketExpectation: staged(PeerRunTicketExpectationPath, 0o600, "ticket"),
		PeerListenerBaseline: staged(PeerListenerBaselinePath, 0o600, "baseline"),
		ListenerAuditor:      staged(ListenerAuditorPath, 0o755, "auditor"),
		ForcedCommandHelper:  staged(ForcedCommandHelperPath, 0o755, "forced"),
		CourierPublicKeyBase64: base64.StdEncoding.EncodeToString(
			publicKey,
		),
		CourierPublicKeyFingerprint: HashHex(publicKey),
	}
	operations, err := NewOSRecoveryOperations(
		manifest,
		testPeerRuntimeConfig(),
		nil,
		&StableDirectory{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if operations.inbox != nil || operations.validated != nil {
		t.Fatal("recovery unexpectedly retained courier authority")
	}
}

func TestSupervisorJournalRejectsDuplicateAndUnsafeAuthorizedKey(t *testing.T) {
	run := testSupervisorRun(t)
	original := testAuthorizedKeysOriginal()
	journal := SupervisorJournal{
		SchemaVersion:           SchemaVersion,
		State:                   SupervisorAccepted,
		RunID:                   run.RunID,
		TicketHash:              run.TicketHash,
		ExpiresAt:               run.ExpiresAt.Unix(),
		AuthorizedKeyLine:       run.AuthorizedKeyLine,
		AuthorizedKeyLineSHA256: HashHex([]byte(run.AuthorizedKeyLine)),
		AuthorizedKeysOriginal:  &original,
	}
	if err := journal.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSupervisorJournal([]byte(
		`{"schema_version":1,"schema_version":1}`,
	)); err == nil {
		t.Fatal("duplicate journal key was accepted")
	}
	journal.AuthorizedKeysOriginal = nil
	if err := journal.Validate(); err == nil {
		t.Fatal("journal without original authorized_keys identity was accepted")
	}
	journal.AuthorizedKeysOriginal = &original
	journal.State = SupervisorChildStarting
	if err := journal.Validate(); err != nil {
		t.Fatal(err)
	}
	journal.AuthorizedKeysOriginal.SHA256 = "tampered"
	if err := journal.Validate(); err == nil {
		t.Fatal("tampered original authorized_keys identity was accepted")
	}
	run.AuthorizedKeyLine = `ssh-ed25519 AAAA` + "\n"
	if ValidAuthorizedKeyLine(run.AuthorizedKeyLine) {
		t.Fatal("unrestricted authorized key was accepted")
	}
}

func TestAuthorizedKeyCrashStateDecisionIsIdempotentAndTamperClosed(t *testing.T) {
	run := testSupervisorRun(t)
	line := []byte(run.AuthorizedKeyLine)
	originalBytes := []byte("ssh-ed25519 foreign-key\n")
	original := testAuthorizedKeysOriginal()
	original.Size = uint64(len(originalBytes))
	original.SHA256 = HashHex(originalBytes)
	installed := append(append([]byte(nil), originalBytes...), line...)
	tests := []struct {
		name           string
		current        []byte
		witness        []byte
		witnessPresent bool
		original       *AuthorizedKeysOriginal
		want           authorizedKeyRecoveryAction
		wantErr        bool
	}{
		{
			name: "accepted-before-witness", current: originalBytes,
			original: &original, want: authorizedKeyNoChange,
		},
		{
			name: "prepared-before-install", current: originalBytes,
			witness: originalBytes, witnessPresent: true, original: &original,
			want: authorizedKeyRemoveWitness,
		},
		{
			name: "installed", current: installed,
			witness: originalBytes, witnessPresent: true, original: &original,
			want: authorizedKeyRestoreAndRemoveWitness,
		},
		{
			name: "restored-before-witness-remove", current: originalBytes,
			witness: originalBytes, witnessPresent: true, original: &original,
			want: authorizedKeyRemoveWitness,
		},
		{
			name: "fully-clean", current: originalBytes, original: &original,
			want: authorizedKeyNoChange,
		},
		{
			name: "missing-witness-with-installed-line", current: installed,
			original: &original, wantErr: true,
		},
		{
			name: "foreign-current-mutation", current: []byte("changed\n"),
			witness: originalBytes, witnessPresent: true, original: &original,
			wantErr: true,
		},
		{
			name: "tampered-witness", current: originalBytes,
			witness: []byte("tampered\n"), witnessPresent: true,
			original: &original, wantErr: true,
		},
		{
			name:    "missing-witness-after-foreign-mutation",
			current: []byte("changed\n"), original: &original, wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action, err := decideAuthorizedKeyRecovery(
				test.current,
				test.witness,
				line,
				test.witnessPresent,
				test.original,
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}
			if !test.wantErr && action != test.want {
				t.Fatalf("unexpected action: got=%d want=%d", action, test.want)
			}
		})
	}
	clear(installed)
}

func newTestSupervisorStore(t *testing.T) SupervisorJournalStore {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return NewSupervisorJournalStore(
		filepath.Join(parent, "peer-journal.json"),
		false,
	)
}

func testSupervisorRun(t *testing.T) SupervisorRun {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	sshPublic, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyBody := string(ssh.MarshalAuthorizedKey(sshPublic))
	line := `from="127.0.0.1",restrict,command="` +
		ForcedCommandHelperPath + `" ` + keyBody
	if !ValidAuthorizedKeyLine(line) {
		t.Fatalf("test line failed validation: %q", line)
	}
	return SupervisorRun{
		RunID:             testRunID,
		TicketHash:        HashHex([]byte("ticket")),
		ExpiresAt:         time.Now().UTC().Add(90 * time.Second),
		AuthorizedKeyLine: line,
	}
}

func testChildIdentity(runID string) ChildIdentity {
	return ChildIdentity{
		PID:           1234,
		StartIdentity: "2026-07-23T00:00:00Z",
		Path:          PeerChildPath,
		Device:        1,
		Inode:         2,
		SHA256:        HashHex([]byte("child")),
		UID:           502,
		SessionID:     1234,
		RunID:         runID,
	}
}

func testAuthorizedKeysOriginal() AuthorizedKeysOriginal {
	return AuthorizedKeysOriginal{
		Device: 1,
		Inode:  2,
		Size:   0,
		UID:    502,
		GID:    20,
		Mode:   0o600,
		SHA256: HashHex(nil),
	}
}
