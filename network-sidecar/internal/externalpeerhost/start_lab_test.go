package externalpeerhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
)

type fakeRunnerClock struct {
	mu          sync.Mutex
	wall        time.Time
	monotonic   time.Duration
	waitAdvance time.Duration
	rollback    bool
}

func (clock *fakeRunnerClock) WallNow() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.wall
}

func (clock *fakeRunnerClock) MonotonicNow() time.Duration {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.monotonic
}

func (clock *fakeRunnerClock) Wait(
	ctx context.Context,
	duration time.Duration,
) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	clock.mu.Lock()
	defer clock.mu.Unlock()
	advance := duration
	if clock.waitAdvance > 0 {
		advance = clock.waitAdvance
	}
	clock.monotonic += advance
	if clock.rollback {
		clock.wall = clock.wall.Add(-time.Second)
		clock.rollback = false
	} else {
		clock.wall = clock.wall.Add(advance)
	}
	return nil
}

type fakeTartResolver struct {
	path  string
	count int
	fail  int
}

func (resolver *fakeTartResolver) Resolve() (string, error) {
	resolver.count++
	if resolver.fail > 0 && resolver.count == resolver.fail {
		return "", ErrUnsafeHostCourier
	}
	return resolver.path, nil
}

type fakeHostExecutor struct {
	t                   *testing.T
	fixture             hostTransactionFixture
	clock               *fakeRunnerClock
	tartPath            string
	specs               []CommandSpec
	events              []string
	creates             map[string][]byte
	awaitingRole        string
	phase               string
	remoteCount         int
	tartCount           int
	readyMisses         int
	nonemptyReady       bool
	neverRunning        bool
	statusError         bool
	driftAtRemote       int
	guestSkew           time.Duration
	failCreate          string
	failCreateHit       bool
	cancelAfterPeerWake context.CancelFunc
}

func (executor *fakeHostExecutor) Run(
	_ context.Context,
	spec CommandSpec,
) (CommandResult, error) {
	executor.t.Helper()
	if err := validateCommandSpec(spec, executor.tartPath); err != nil {
		executor.t.Fatalf("runner emitted an open command spec: %#v", spec)
	}
	executor.specs = append(executor.specs, cloneCommandSpec(spec))
	if spec.Purpose == CommandTartARP {
		if executor.awaitingRole != "" {
			executor.t.Fatal("Tart resolution was not consumed by one SSH operation")
		}
		executor.awaitingRole = spec.Role
		executor.tartCount++
		config := executor.roleConfig(spec.Role)
		return CommandResult{Stdout: []byte(config.IPv4 + "\n")}, nil
	}
	executor.remoteCount++
	if executor.awaitingRole != spec.Role {
		executor.t.Fatal("remote operation was not immediately preceded by role Tart ARP")
	}
	executor.awaitingRole = ""
	config := executor.roleConfig(spec.Role)
	identity := remoteIdentity{
		Model: "VirtualMac2,1", Architecture: "arm64",
		PlatformUUID: config.PlatformUUID,
		MAC:          config.MAC, IPv4: config.IPv4,
		SSHHostFingerprint: config.SSHHostFingerprint,
		ConsoleUser:        managementConsoleUser,
		ConsoleUID:         executor.fixture.input.Config.ConsoleUID,
		UnixTime: executor.clock.WallNow().
			Add(executor.guestSkew).
			Unix(),
	}
	if executor.driftAtRemote > 0 &&
		executor.remoteCount == executor.driftAtRemote {
		identity.MAC = "02:00:00:00:00:fe"
	}
	key := spec.Role + "|" + spec.RemotePath
	if spec.Purpose == CommandRemoteCreate {
		if executor.failCreate == spec.RemotePath &&
			!executor.failCreateHit {
			executor.failCreateHit = true
			return CommandResult{}, ErrUnsafeHostCourier
		}
		if _, exists := executor.creates[key]; exists {
			return CommandResult{}, &CommandExitError{Code: 45}
		}
		executor.creates[key] = append([]byte(nil), spec.Stdin...)
		executor.events = append(
			executor.events,
			"create:"+spec.Role+":"+spec.RemotePath,
		)
		switch spec.RemotePath {
		case externalpeer.PeerWakeTrigger:
			if executor.neverRunning {
				executor.phase = "starting"
			} else if executor.statusError {
				executor.phase = "status-error"
			} else {
				executor.phase = "running"
			}
			if executor.cancelAfterPeerWake != nil {
				executor.cancelAfterPeerWake()
				executor.cancelAfterPeerWake = nil
			}
		case externalpeer.PeerCancelTrigger,
			filepath.Join(
				vmexternalpeerlab.ClientInboxRoot,
				vmexternalpeerlab.PeerReadyName,
			):
			executor.phase = "clean-postflight"
		}
		return CommandResult{
			Stdout: encodeRemoteFrameForTest(identity, nil),
		}, nil
	}
	payload, found := executor.readPayload(spec.Role, spec.RemotePath)
	if !found {
		return CommandResult{}, &CommandExitError{Code: 44}
	}
	executor.events = append(
		executor.events,
		"read:"+spec.Role+":"+spec.RemotePath,
	)
	return CommandResult{
		Stdout: encodeRemoteFrameForTest(identity, payload),
	}, nil
}

func (executor *fakeHostExecutor) roleConfig(
	role string,
) externalpeer.SupervisorVMConfig {
	switch role {
	case "client":
		return executor.fixture.input.Config.Client
	case "peer":
		return executor.fixture.input.Config.Peer
	default:
		executor.t.Fatalf("unexpected role: %q", role)
		return externalpeer.SupervisorVMConfig{}
	}
}

func (executor *fakeHostExecutor) readPayload(
	role string,
	path string,
) ([]byte, bool) {
	if role == "peer" && path == externalpeer.PeerPublicStatus {
		status := externalpeer.PeerSupervisorStatus{
			SchemaVersion: externalpeer.SchemaVersion,
		}
		switch executor.phase {
		case "", "idle-ready":
			status.State = "idle-ready"
		case "starting":
			status.State = "starting"
			status.RunID = hostTestRunID
		case "running":
			status.State = "running"
			status.RunID = hostTestRunID
		case "clean-postflight":
			status.State = "clean-postflight"
			status.RunID = hostTestRunID
		case "status-error":
			status.State = "recovery-only"
			status.RunID = hostTestRunID
			status.ErrorCode = "peer-start-refused"
		default:
			executor.t.Fatalf("unknown fake peer phase: %q", executor.phase)
		}
		data, err := json.Marshal(status)
		if err != nil {
			executor.t.Fatal(err)
		}
		return append(data, '\n'), true
	}
	if role == "client" &&
		path == filepath.Join(
			vmexternalpeerlab.ClientOutboxRoot,
			vmexternalpeerlab.ClientReadyName,
		) {
		if executor.readyMisses > 0 {
			executor.readyMisses--
			return nil, false
		}
		if executor.nonemptyReady {
			return []byte("unexpected"), true
		}
		return nil, true
	}
	if role == "client" {
		for index, name := range []string{
			externalpeer.ClientArtifactNames[0],
			externalpeer.ClientArtifactNames[1],
			externalpeer.ClientArtifactNames[2],
			vmexternalpeerlab.ClientManifestName,
		} {
			if path != filepath.Join(vmexternalpeerlab.ClientOutboxRoot, name) {
				continue
			}
			values := [][]byte{
				executor.fixture.input.ClientArtifacts.Descriptor,
				executor.fixture.input.ClientArtifacts.TLSClientCSRDER,
				executor.fixture.input.ClientArtifacts.OverlayClientPublicKey,
				executor.fixture.input.ClientManifest,
			}
			return append([]byte(nil), values[index]...), true
		}
	}
	if role == "peer" {
		values := [][]byte{
			executor.fixture.peer.Descriptor,
			executor.fixture.peer.CADER,
			executor.fixture.peer.ServerCertificateDER,
			executor.fixture.peer.ClientCertificateDER,
			executor.fixture.peer.OverlayServerPublicKey,
			executor.fixture.peer.SystemSSHHostPublicKey,
			executor.fixture.peer.TransferManifest,
		}
		for index, name := range externalpeer.PeerArtifactNames {
			if path == filepath.Join(externalpeer.PeerPublicOutbox, name) {
				return append([]byte(nil), values[index]...), true
			}
		}
	}
	return nil, false
}

func cloneCommandSpec(spec CommandSpec) CommandSpec {
	spec.Arguments = append([]string(nil), spec.Arguments...)
	spec.Environment = append([]string(nil), spec.Environment...)
	spec.Stdin = append([]byte(nil), spec.Stdin...)
	return spec
}

func TestStartLabRunnerCompletesSequentialCreateOnlyTransaction(
	t *testing.T,
) {
	t.Parallel()
	fixture := newHostTransactionFixture(t)
	layout := prepareStartLabWorkspace(t, fixture)
	clock := &fakeRunnerClock{wall: fixture.now}
	executor, resolver := newFakeHostRuntime(t, layout, fixture, clock)
	runner, err := NewStartLabRunner(
		layout,
		executor,
		clock,
		resolver,
		nonceEntropy(1, 2, 3, 4),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.StartLab(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resolver.count != executor.remoteCount ||
		executor.tartCount != executor.remoteCount ||
		executor.awaitingRole != "" {
		t.Fatalf(
			"not every SSH operation had fresh Tart ARP: resolve=%d tart=%d remote=%d pending=%q",
			resolver.count,
			executor.tartCount,
			executor.remoteCount,
			executor.awaitingRole,
		)
	}
	assertCommandClosure(t, executor.specs, resolver.path)
	assertEventBefore(
		t,
		executor.events,
		"read:peer:"+filepath.Join(
			externalpeer.PeerPublicOutbox,
			externalpeer.PeerArtifactNames[len(externalpeer.PeerArtifactNames)-1],
		),
		"create:client:"+filepath.Join(
			vmexternalpeerlab.ClientInboxRoot,
			vmexternalpeerlab.PeerEnvelopeName,
		),
	)
	cancelKey := "peer|" + externalpeer.PeerCancelEnvelope
	if _, exists := executor.creates[cancelKey]; exists {
		t.Fatal("success path pre-signed or delivered sequence 3")
	}
	assertEnvelopeKinds(
		t,
		layout,
		successEnvelopeNames,
		[]externalpeer.CourierKind{
			externalpeer.CourierRunTicket,
			externalpeer.CourierClientToPeer,
			externalpeer.CourierPeerToClient,
		},
		fixture.now,
	)
	if err := runner.StartLab(context.Background()); err == nil {
		t.Fatal("one-shot runner accepted a repeated transaction")
	}
}

func TestStartLabRunnerRejectsNonemptyReadyBeforeSigning(t *testing.T) {
	t.Parallel()
	fixture := newHostTransactionFixture(t)
	layout := prepareStartLabWorkspace(t, fixture)
	clock := &fakeRunnerClock{wall: fixture.now}
	executor, resolver := newFakeHostRuntime(t, layout, fixture, clock)
	executor.nonemptyReady = true
	runner, err := NewStartLabRunner(
		layout,
		executor,
		clock,
		resolver,
		nonceEntropy(1, 2, 3, 4),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.StartLab(context.Background()); err == nil {
		t.Fatal("nonempty client ready marker was accepted")
	}
	assertDirectoryNames(t, layout.Envelopes, nil)
}

func TestStartLabRunnerCancellationBranchesAreStrictlySequenced(
	t *testing.T,
) {
	t.Parallel()
	t.Run("cancel before peer response forbids sequence 2", func(t *testing.T) {
		fixture := newHostTransactionFixture(t)
		layout := prepareStartLabWorkspace(t, fixture)
		clock := &fakeRunnerClock{wall: fixture.now}
		executor, resolver := newFakeHostRuntime(t, layout, fixture, clock)
		executor.neverRunning = true
		runner, err := NewStartLabRunner(
			layout,
			executor,
			clock,
			resolver,
			nonceEntropy(11, 12, 13, 14),
		)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		executor.cancelAfterPeerWake = cancel
		defer cancel()
		if err := runner.StartLab(ctx); err == nil {
			t.Fatal("cancelled transaction reported success")
		}
		assertEnvelopeKinds(
			t,
			layout,
			cancelEnvelopeNames,
			[]externalpeer.CourierKind{
				externalpeer.CourierRunTicket,
				externalpeer.CourierClientToPeer,
				externalpeer.CourierCancel,
			},
			fixture.now,
		)
		peerEnvelopeKey := "client|" + filepath.Join(
			vmexternalpeerlab.ClientInboxRoot,
			vmexternalpeerlab.PeerEnvelopeName,
		)
		if _, exists := executor.creates[peerEnvelopeKey]; exists {
			t.Fatal("sequence 2 was delivered after pre-peer cancellation")
		}
		assertSingleCancelDelivery(t, executor)
	})
	t.Run("cancel after sequence 2 retains peer response", func(t *testing.T) {
		fixture := newHostTransactionFixture(t)
		layout := prepareStartLabWorkspace(t, fixture)
		clock := &fakeRunnerClock{wall: fixture.now}
		executor, resolver := newFakeHostRuntime(t, layout, fixture, clock)
		executor.failCreate = filepath.Join(
			vmexternalpeerlab.ClientInboxRoot,
			vmexternalpeerlab.PeerReadyName,
		)
		runner, err := NewStartLabRunner(
			layout,
			executor,
			clock,
			resolver,
			nonceEntropy(21, 22, 23, 24),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := runner.StartLab(context.Background()); err == nil {
			t.Fatal("failed client delivery reported success")
		}
		assertEnvelopeKinds(
			t,
			layout,
			successCancelEnvelopeNames,
			[]externalpeer.CourierKind{
				externalpeer.CourierRunTicket,
				externalpeer.CourierClientToPeer,
				externalpeer.CourierPeerToClient,
				externalpeer.CourierCancel,
			},
			fixture.now,
		)
		peerEnvelopeKey := "client|" + filepath.Join(
			vmexternalpeerlab.ClientInboxRoot,
			vmexternalpeerlab.PeerEnvelopeName,
		)
		if _, exists := executor.creates[peerEnvelopeKey]; !exists {
			t.Fatal("post-sequence-2 cancellation discarded peer response")
		}
		assertSingleCancelDelivery(t, executor)
	})
}

func TestStartLabRunnerFailsClosedOnIdentityClockStatusAndTimeout(
	t *testing.T,
) {
	t.Parallel()
	t.Run("same-session identity drift", func(t *testing.T) {
		fixture := newHostTransactionFixture(t)
		layout := prepareStartLabWorkspace(t, fixture)
		clock := &fakeRunnerClock{wall: fixture.now}
		executor, resolver := newFakeHostRuntime(t, layout, fixture, clock)
		executor.driftAtRemote = 2
		runner, err := NewStartLabRunner(
			layout, executor, clock, resolver, nonceEntropy(1, 2, 3, 4),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := runner.StartLab(context.Background()); err == nil {
			t.Fatal("guest identity drift was accepted")
		}
		assertDirectoryNames(t, layout.Envelopes, nil)
	})
	t.Run("host wall rollback", func(t *testing.T) {
		fixture := newHostTransactionFixture(t)
		layout := prepareStartLabWorkspace(t, fixture)
		clock := &fakeRunnerClock{wall: fixture.now, rollback: true}
		executor, resolver := newFakeHostRuntime(t, layout, fixture, clock)
		executor.readyMisses = 1
		runner, err := NewStartLabRunner(
			layout, executor, clock, resolver, nonceEntropy(1, 2, 3, 4),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := runner.StartLab(context.Background()); err == nil {
			t.Fatal("wall-clock rollback was accepted")
		}
		assertDirectoryNames(t, layout.Envelopes, nil)
	})
	t.Run("guest wall skew over 30 seconds", func(t *testing.T) {
		fixture := newHostTransactionFixture(t)
		layout := prepareStartLabWorkspace(t, fixture)
		clock := &fakeRunnerClock{wall: fixture.now}
		executor, resolver := newFakeHostRuntime(t, layout, fixture, clock)
		executor.guestSkew = 31 * time.Second
		runner, err := NewStartLabRunner(
			layout, executor, clock, resolver, nonceEntropy(1, 2, 3, 4),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := runner.StartLab(context.Background()); err == nil {
			t.Fatal("guest wall skew over 30 seconds was accepted")
		}
		assertDirectoryNames(t, layout.Envelopes, nil)
	})
	t.Run("peer status error triggers cancellation", func(t *testing.T) {
		fixture := newHostTransactionFixture(t)
		layout := prepareStartLabWorkspace(t, fixture)
		clock := &fakeRunnerClock{wall: fixture.now}
		executor, resolver := newFakeHostRuntime(t, layout, fixture, clock)
		executor.statusError = true
		runner, err := NewStartLabRunner(
			layout, executor, clock, resolver, nonceEntropy(1, 2, 3, 4),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := runner.StartLab(context.Background()); err == nil {
			t.Fatal("peer recovery-only status reported success")
		}
		assertSingleCancelDelivery(t, executor)
	})
	t.Run("monotonic 120-second ceiling", func(t *testing.T) {
		fixture := newHostTransactionFixture(t)
		layout := prepareStartLabWorkspace(t, fixture)
		clock := &fakeRunnerClock{
			wall: fixture.now, waitAdvance: 30 * time.Second,
		}
		executor, resolver := newFakeHostRuntime(t, layout, fixture, clock)
		executor.neverRunning = true
		runner, err := NewStartLabRunner(
			layout, executor, clock, resolver, nonceEntropy(1, 2, 3, 4),
		)
		if err != nil {
			t.Fatal(err)
		}
		err = runner.StartLab(context.Background())
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unexpected timeout result: %v", err)
		}
		if clock.MonotonicNow() < startupBudget {
			t.Fatal("runner stopped before the fixed monotonic ceiling")
		}
	})
}

func prepareStartLabWorkspace(
	t *testing.T,
	fixture hostTransactionFixture,
) Layout {
	t.Helper()
	layout := testLayout(t)
	if err := InitializeKeyStore(
		layout,
		bytes.NewReader(bytes.Repeat([]byte{0x71}, 64)),
	); err != nil {
		t.Fatal(err)
	}
	prepareManagementPinFixture(t, layout, fixture)
	if err := PinReviewedManagementHostKeys(layout); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		layout.ClientPublic,
		layout.PeerPublic,
		layout.Envelopes,
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(layout.Workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	return layout
}

func newFakeHostRuntime(
	t *testing.T,
	layout Layout,
	fixture hostTransactionFixture,
	clock *fakeRunnerClock,
) (*fakeHostExecutor, *fakeTartResolver) {
	t.Helper()
	tartPath := filepath.Join(
		layout.RepositoryRoot,
		filepath.FromSlash(fixedTartRelativePath),
	)
	executor := &fakeHostExecutor{
		t: t, fixture: fixture, clock: clock, tartPath: tartPath,
		creates: make(map[string][]byte), phase: "idle-ready",
	}
	t.Cleanup(func() {
		for key, data := range executor.creates {
			clear(data)
			delete(executor.creates, key)
		}
		for index := range executor.specs {
			clear(executor.specs[index].Stdin)
		}
	})
	return executor, &fakeTartResolver{path: tartPath}
}

func assertCommandClosure(
	t *testing.T,
	specs []CommandSpec,
	tartPath string,
) {
	t.Helper()
	if len(specs) == 0 || len(specs)%2 != 0 {
		t.Fatalf("unexpected command count: %d", len(specs))
	}
	for index, spec := range specs {
		if err := validateCommandSpec(spec, tartPath); err != nil {
			t.Fatalf("invalid command %d: %#v", index, spec)
		}
		if index%2 == 0 && spec.Purpose != CommandTartARP {
			t.Fatalf("command %d was not Tart ARP", index)
		}
		if index%2 == 1 &&
			spec.Purpose != CommandRemoteRead &&
			spec.Purpose != CommandRemoteCreate {
			t.Fatalf("command %d was not fixed SSH", index)
		}
		joined := strings.Join(spec.Arguments, "\x00")
		if strings.Contains(joined, "sshpass") ||
			strings.Contains(joined, "sudo") ||
			strings.Contains(joined, "net-bridged") {
			t.Fatalf("command %d gained mutable or privileged authority", index)
		}
	}
}

func assertEventBefore(
	t *testing.T,
	events []string,
	before string,
	after string,
) {
	t.Helper()
	beforeIndex := -1
	afterIndex := -1
	for index, event := range events {
		if event == before {
			beforeIndex = index
		}
		if event == after {
			afterIndex = index
		}
	}
	if beforeIndex < 0 || afterIndex < 0 || beforeIndex >= afterIndex {
		t.Fatalf(
			"event order invalid: before=%d after=%d events=%v",
			beforeIndex,
			afterIndex,
			events,
		)
	}
}

func assertSingleCancelDelivery(
	t *testing.T,
	executor *fakeHostExecutor,
) {
	t.Helper()
	cancelEnvelope := executor.creates["peer|"+externalpeer.PeerCancelEnvelope]
	if len(cancelEnvelope) == 0 {
		t.Fatal("sequence 3 cancel envelope was not delivered")
	}
	cancelTriggerKey := "peer|" + externalpeer.PeerCancelTrigger
	if _, exists := executor.creates[cancelTriggerKey]; !exists {
		t.Fatal("fixed cancel wake was not delivered")
	}
	count := 0
	for _, event := range executor.events {
		if event == "create:peer:"+externalpeer.PeerCancelEnvelope {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("cancel envelope delivery count=%d", count)
	}
}

func assertEnvelopeKinds(
	t *testing.T,
	layout Layout,
	names []string,
	kinds []externalpeer.CourierKind,
	now time.Time,
) {
	t.Helper()
	assertDirectoryNames(t, layout.Envelopes, names)
	public, err := os.ReadFile(filepath.Join(layout.PrivateRoot, PublicKeyName))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(public)
	for index, name := range names {
		data, err := os.ReadFile(filepath.Join(layout.Envelopes, name))
		if err != nil {
			t.Fatal(err)
		}
		message, err := externalpeer.VerifyCourierMessage(data, public, now)
		clear(data)
		if err != nil {
			t.Fatal(err)
		}
		if message.Kind != kinds[index] {
			t.Fatalf(
				"envelope %q kind=%d, want %d",
				name,
				message.Kind,
				kinds[index],
			)
		}
	}
}

func assertDirectoryNames(
	t *testing.T,
	path string,
	expected []string,
) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		actual = append(actual, entry.Name())
	}
	want := append([]string(nil), expected...)
	sort.Strings(actual)
	sort.Strings(want)
	if !equalStrings(actual, want) {
		t.Fatalf("directory names=%v, want %v", actual, want)
	}
}

func TestParseTartARPRejectsOverlayLoopbackAndMutableOutput(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"10.88.0.2\n",
		"127.0.0.1\n",
		"192.168.64.11 extra\n",
		"192.168.64.11\n192.168.64.12\n",
		"8.8.8.8\n",
	} {
		if _, err := parseTartARP([]byte(value)); err == nil {
			t.Fatalf("unsafe Tart ARP output was accepted: %q", value)
		}
	}
	address, err := parseTartARP([]byte("192.168.64.11\n"))
	if err != nil || address != netip.MustParseAddr("192.168.64.11") {
		t.Fatalf("valid private ARP result refused: %v %v", address, err)
	}
}

var _ RunnerClock = (*fakeRunnerClock)(nil)
var _ TartResolver = (*fakeTartResolver)(nil)
var _ CommandExecutor = (*fakeHostExecutor)(nil)
