package externalpeerhost

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/externalpeergueststaging"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
	"golang.org/x/crypto/ssh"
)

type layerBHostFacts struct {
	uuid        string
	mac         string
	ip          netip.Addr
	fingerprint string
	witness     []byte
}

type layerBFakeExecutor struct {
	tartPath  string
	clock     *fakeRunnerClock
	client    layerBHostFacts
	peer      layerBHostFacts
	awaiting  string
	tartCalls int
	sshCalls  int
}

func (executor *layerBFakeExecutor) Run(
	_ context.Context,
	spec CommandSpec,
) (CommandResult, error) {
	if validateCommandSpec(spec, executor.tartPath) != nil {
		return CommandResult{}, ErrUnsafeHostCourier
	}
	facts := executor.client
	if spec.Role == "peer" {
		facts = executor.peer
	} else if spec.Role != "client" {
		return CommandResult{}, ErrUnsafeHostCourier
	}
	if spec.Purpose == CommandTartARP {
		executor.tartCalls++
		executor.awaiting = spec.Role
		return CommandResult{
			Stdout: []byte(facts.ip.String() + "\n"),
		}, nil
	}
	if spec.Purpose != CommandRemoteRead ||
		executor.awaiting != spec.Role ||
		spec.RemotePath == "" ||
		len(spec.Stdin) != 0 {
		return CommandResult{}, ErrUnsafeHostCourier
	}
	executor.awaiting = ""
	executor.sshCalls++
	return CommandResult{Stdout: encodeRemoteFrameForTest(
		remoteIdentity{
			Model:              "VirtualMac2,1",
			Architecture:       "arm64",
			PlatformUUID:       facts.uuid,
			MAC:                facts.mac,
			IPv4:               facts.ip.String(),
			SSHHostFingerprint: facts.fingerprint,
			ConsoleUser:        managementConsoleUser,
			ConsoleUID:         501,
			UnixTime:           executor.clock.WallNow().Unix(),
		},
		facts.witness,
	)}, nil
}

func TestLayerBInputInitializationPublishesPrepareThenReviewedPin(t *testing.T) {
	t.Parallel()
	fixture := prepareBuildInputFixture(t)
	prepareLayerAKeyAndPublicInputs(t, fixture.layout)
	if err := InitializeLayerAInputs(fixture.layout); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	client, peer := prepareBaseGuestReviews(t, fixture, now)
	clock := &fakeRunnerClock{wall: now}
	tartPath, err := fixedTartPath(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	executor := &layerBFakeExecutor{
		tartPath: tartPath,
		clock:    clock,
		client:   client,
		peer:     peer,
	}
	resolver := &fakeTartResolver{path: tartPath}
	assertLayerBLocalPreflight(t, fixture.layout, client.ip, peer.ip)
	state, err := InitializeLayerBInputs(
		context.Background(),
		fixture.layout,
		executor,
		clock,
		resolver,
	)
	if err != nil {
		t.Fatal(err)
	}
	if state != LayerBManagementHostKeyPinRequired {
		t.Fatalf("unexpected first Layer B state: %q", state)
	}
	if executor.tartCalls != 2 || executor.sshCalls != 0 {
		t.Fatalf(
			"unreviewed host key reached SSH: tart=%d ssh=%d",
			executor.tartCalls,
			executor.sshCalls,
		)
	}
	assertDirectoryNames(
		t,
		fixture.layout.Management,
		managementPrivateNames,
	)
	if !pathAbsent(filepath.Join(
		fixture.layout.GuestShare,
		LayerBPrepareInputsName,
	)) {
		t.Fatal("unreviewed host key published prepare inputs")
	}
	if err := PinReviewedManagementHostKeys(fixture.layout); err != nil {
		t.Fatal(err)
	}
	state, err = InitializeLayerBInputs(
		context.Background(),
		fixture.layout,
		executor,
		clock,
		resolver,
	)
	if err != nil || state != LayerBPreparePublished {
		t.Fatalf("post-pin prepare failed: state=%q err=%v", state, err)
	}
	assertLayerBCollection(
		t,
		fixture.layout,
		LayerBPrepareInputsName,
		false,
	)
	if executor.tartCalls != 6 || executor.sshCalls != 2 {
		t.Fatalf(
			"prepare did not bind every SSH proof to fresh ARP: tart=%d ssh=%d",
			executor.tartCalls,
			executor.sshCalls,
		)
	}
	state, err = InitializeLayerBInputs(
		context.Background(),
		fixture.layout,
		executor,
		clock,
		resolver,
	)
	if err != nil || state != LayerBPreparePublished {
		t.Fatalf("prepare reentry failed: state=%q err=%v", state, err)
	}
	addPreparedGuestReviews(t, fixture.layout)
	state, err = InitializeLayerBInputs(
		context.Background(),
		fixture.layout,
		executor,
		clock,
		resolver,
	)
	if err != nil {
		t.Fatal(err)
	}
	if state != LayerBListenerBaselineApprovalRequired {
		t.Fatalf("unexpected reviewed Layer B state: %q", state)
	}
	if !pathAbsent(fixture.layout.ListenerApproval) ||
		!pathAbsent(filepath.Join(
			fixture.layout.GuestShare,
			LayerBPinInputsName,
		)) {
		t.Fatal("one layer-b call crossed candidate review into approval or pin")
	}
	if err := ApproveLayerBListenerBaselines(
		context.Background(),
		fixture.layout,
		executor,
		clock,
		resolver,
	); err != nil {
		t.Fatal(err)
	}
	if pathAbsent(fixture.layout.ListenerApproval) ||
		!pathAbsent(filepath.Join(
			fixture.layout.GuestShare,
			LayerBPinInputsName,
		)) {
		t.Fatal("approval command published pin inputs or no approval record")
	}
	if err := ApproveLayerBListenerBaselines(
		context.Background(),
		fixture.layout,
		executor,
		clock,
		resolver,
	); err != nil {
		t.Fatalf("identical approval reentry failed: %v", err)
	}
	state, err = InitializeLayerBInputs(
		context.Background(),
		fixture.layout,
		executor,
		clock,
		resolver,
	)
	if err != nil || state != LayerBPinPublished {
		t.Fatalf("approved pin publication failed: state=%q err=%v", state, err)
	}
	assertLayerBCollection(
		t,
		fixture.layout,
		LayerBPinInputsName,
		true,
	)
	if validateNoPrivateKeyMaterial(fixture.layout.GuestShare) != nil {
		t.Fatal("guest share contains private-key material")
	}
}

func TestLayerBInputInitializationRejectsRoleSwapAndReviewedTamper(
	t *testing.T,
) {
	t.Parallel()
	t.Run("approval refuses unpinned management host keys", func(t *testing.T) {
		fixture := prepareBuildInputFixture(t)
		prepareLayerAKeyAndPublicInputs(t, fixture.layout)
		if err := InitializeLayerAInputs(fixture.layout); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		client, peer := prepareBaseGuestReviews(t, fixture, now)
		executor, clock, resolver := newLayerBFakeRuntime(
			t,
			fixture.layout,
			now,
			client,
			peer,
		)
		state, err := InitializeLayerBInputs(
			context.Background(),
			fixture.layout,
			executor,
			clock,
			resolver,
		)
		if err != nil || state != LayerBManagementHostKeyPinRequired {
			t.Fatalf("review import failed: state=%q err=%v", state, err)
		}
		addPreparedGuestReviews(t, fixture.layout)
		if err := ApproveLayerBListenerBaselines(
			context.Background(),
			fixture.layout,
			executor,
			clock,
			resolver,
		); err == nil {
			t.Fatal("listener approval accepted unpinned management host keys")
		}
		if executor.sshCalls != 0 {
			t.Fatal("listener approval attempted TOFU SSH")
		}
		if !pathAbsent(fixture.layout.ListenerApproval) {
			t.Fatal("listener approval was published before host-key pinning")
		}
	})
	t.Run("role swap", func(t *testing.T) {
		fixture := prepareBuildInputFixture(t)
		prepareLayerAKeyAndPublicInputs(t, fixture.layout)
		if err := InitializeLayerAInputs(fixture.layout); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		client, peer := prepareBaseGuestReviews(t, fixture, now)
		path := filepath.Join(
			fixture.layout.GuestPeerOutput,
			externalpeergueststaging.VMIdentityWitnessName,
		)
		var witness hostVMIdentityWitness
		readJSONTestFile(t, path, &witness)
		witness.Role = externalpeergueststaging.ClientRole
		writeJSONTestFile(t, path, witness)
		executor, clock, resolver := newLayerBFakeRuntime(
			t,
			fixture.layout,
			now,
			client,
			peer,
		)
		if _, err := InitializeLayerBInputs(
			context.Background(),
			fixture.layout,
			executor,
			clock,
			resolver,
		); err == nil {
			t.Fatal("role-swapped guest review was accepted")
		}
		if executor.tartCalls != 0 || executor.sshCalls != 0 {
			t.Fatal("role swap reached Tart/SSH")
		}
	})
	t.Run("review witness tamper", func(t *testing.T) {
		fixture := prepareBuildInputFixture(t)
		prepareLayerAKeyAndPublicInputs(t, fixture.layout)
		if err := InitializeLayerAInputs(fixture.layout); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		client, peer := prepareBaseGuestReviews(t, fixture, now)
		executor, clock, resolver := newLayerBFakeRuntime(
			t,
			fixture.layout,
			now,
			client,
			peer,
		)
		assertLayerBLocalPreflight(t, fixture.layout, client.ip, peer.ip)
		state, err := InitializeLayerBInputs(
			context.Background(),
			fixture.layout,
			executor,
			clock,
			resolver,
		)
		if err != nil || state != LayerBManagementHostKeyPinRequired {
			t.Fatalf("review import failed: state=%q err=%v", state, err)
		}
		if err := PinReviewedManagementHostKeys(fixture.layout); err != nil {
			t.Fatal(err)
		}
		state, err = InitializeLayerBInputs(
			context.Background(),
			fixture.layout,
			executor,
			clock,
			resolver,
		)
		if err != nil || state != LayerBPreparePublished {
			t.Fatalf("prepare failed: state=%q err=%v", state, err)
		}
		addPreparedGuestReviews(t, fixture.layout)
		path := filepath.Join(
			fixture.layout.GuestPeerOutput,
			externalpeergueststaging.ReviewWitnessName,
		)
		var witness hostLayerBReviewWitness
		readJSONTestFile(t, path, &witness)
		witness.BaselineSHA256 = repeatHex("f", 64)
		writeJSONTestFile(t, path, witness)
		if _, err := InitializeLayerBInputs(
			context.Background(),
			fixture.layout,
			executor,
			clock,
			resolver,
		); err == nil {
			t.Fatal("tampered reviewed baseline binding was accepted")
		}
		if !pathAbsent(filepath.Join(
			fixture.layout.GuestShare,
			LayerBPinInputsName,
		)) {
			t.Fatal("tamper failure published pin inputs")
		}
	})
	t.Run("approved baseline tamper is never replaced", func(t *testing.T) {
		fixture := prepareBuildInputFixture(t)
		prepareLayerAKeyAndPublicInputs(t, fixture.layout)
		if err := InitializeLayerAInputs(fixture.layout); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		client, peer := prepareBaseGuestReviews(t, fixture, now)
		executor, clock, resolver := newLayerBFakeRuntime(
			t,
			fixture.layout,
			now,
			client,
			peer,
		)
		state, err := InitializeLayerBInputs(
			context.Background(),
			fixture.layout,
			executor,
			clock,
			resolver,
		)
		if err != nil || state != LayerBManagementHostKeyPinRequired {
			t.Fatalf("review import failed: state=%q err=%v", state, err)
		}
		if err := PinReviewedManagementHostKeys(fixture.layout); err != nil {
			t.Fatal(err)
		}
		state, err = InitializeLayerBInputs(
			context.Background(),
			fixture.layout,
			executor,
			clock,
			resolver,
		)
		if err != nil || state != LayerBPreparePublished {
			t.Fatalf("prepare failed: state=%q err=%v", state, err)
		}
		addPreparedGuestReviews(t, fixture.layout)
		state, err = InitializeLayerBInputs(
			context.Background(),
			fixture.layout,
			executor,
			clock,
			resolver,
		)
		if err != nil || state != LayerBListenerBaselineApprovalRequired {
			t.Fatalf("approval gate failed: state=%q err=%v", state, err)
		}
		if err := ApproveLayerBListenerBaselines(
			context.Background(),
			fixture.layout,
			executor,
			clock,
			resolver,
		); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(
			fixture.layout.ListenerApproval,
			ClientApprovedBaselineName,
		)
		tampered, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		tampered[len(tampered)-2] ^= 1
		if err := os.WriteFile(target, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ApproveLayerBListenerBaselines(
			context.Background(),
			fixture.layout,
			executor,
			clock,
			resolver,
		); err == nil {
			t.Fatal("approval reentry replaced a tampered approval")
		}
		after, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(tampered) {
			t.Fatal("tampered approved baseline was overwritten")
		}
		if _, err := InitializeLayerBInputs(
			context.Background(),
			fixture.layout,
			executor,
			clock,
			resolver,
		); err == nil {
			t.Fatal("tampered approval published pin inputs")
		}
	})
}

func assertLayerBLocalPreflight(
	t *testing.T,
	layout Layout,
	clientIP netip.Addr,
	peerIP netip.Addr,
) {
	t.Helper()
	builds, err := loadExternalPeerBuildInputs(layout)
	if err != nil {
		t.Fatalf("build preflight: %v", err)
	}
	courier, management, err := loadPublicInputKeys(layout)
	if err != nil {
		t.Fatalf("public-key preflight: %v", err)
	}
	defer clear(courier)
	defer clearByteSlices(management)
	client, err := openGuestReviewSet(layout, "client", builds, management[0])
	if err != nil {
		t.Fatalf("client review preflight: %v", err)
	}
	defer client.close()
	peer, err := openGuestReviewSet(layout, "peer", builds, management[1])
	if err != nil {
		t.Fatalf("peer review preflight: %v", err)
	}
	defer peer.close()
	_, config, err := buildLayerBConfig(client, peer, clientIP, peerIP)
	if err != nil {
		t.Fatalf("config preflight: %v", err)
	}
	defer clear(config)
	if _, expectation, err := buildRunTicketExpectation(
		builds,
		config,
	); err != nil {
		t.Fatalf("expectation preflight: %v", err)
	} else {
		clear(expectation)
	}
}

func prepareBaseGuestReviews(
	t *testing.T,
	fixture buildInputFixture,
	now time.Time,
) (layerBHostFacts, layerBHostFacts) {
	t.Helper()
	values := make([]layerBHostFacts, 0, 2)
	for _, role := range []string{"client", "peer"} {
		root := fixture.layout.GuestClientOutput
		expectedRole := externalpeergueststaging.ClientRole
		runtimeTarget := vmexternalpeerlab.RuntimeTarget
		uuid := hostTestClientUUID
		mac := hostTestClientMAC
		ip := hostTestClientIP
		publicName := ClientManagementPublicName
		allowed := []string{managementConsoleUser}
		restricted := false
		regenerated := false
		if role == "peer" {
			root = fixture.layout.GuestPeerOutput
			expectedRole = externalpeergueststaging.PeerRole
			runtimeTarget = vmexternalpeerlab.PeerRuntimeTarget
			uuid = hostTestPeerUUID
			mac = hostTestPeerMAC
			ip = hostTestPeerIP
			publicName = PeerManagementPublicName
			allowed = []string{managementConsoleUser, "kyclashlabssh"}
			restricted = true
			regenerated = true
		}
		if err := os.MkdirAll(root, 0o700); err != nil ||
			os.Chmod(root, 0o700) != nil {
			t.Fatal("failed to create guest review root")
		}
		_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
		clear(hostPrivate)
		if err != nil {
			t.Fatal(err)
		}
		hostPublic := hostSigner.PublicKey().Marshal()
		fingerprint := ssh.FingerprintSHA256(hostSigner.PublicKey())
		appTree := ""
		if role == "client" {
			var manifest appTreeManifest
			readJSONTestFile(
				t,
				filepath.Join(fixture.appRun, AppTreeManifestInputName),
				&manifest,
			)
			appTree = manifest.TreeSHA256
		}
		identity := hostVMIdentityWitness{
			SchemaVersion: 1,
			Role:          expectedRole,
			RuntimeTarget: runtimeTarget,
			CollectedAt:   now.Unix(),
			Identity: externalpeergueststaging.VMIdentity{
				Model:                  "VirtualMac2,1",
				Architecture:           "arm64",
				PlatformUUID:           uuid,
				En0MAC:                 mac,
				En0IPv4:                ip.String(),
				SSHHostPublicKeySHA256: hashBytes(hostPublic),
				SSHHostKeyFingerprint:  fingerprint,
			},
			AppTreeSHA256: appTree,
		}
		identityBytes, err := encodeCanonicalHostJSON(identity)
		if err != nil {
			t.Fatal(err)
		}
		inventoryBytes, err := externalpeer.EncodeListenerInventory(
			externalpeer.ListenerInventory{
				SchemaVersion: externalpeer.SchemaVersion,
				CollectedAt:   now.Unix(),
				Listeners:     nil,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		managementPublic, err := os.ReadFile(
			filepath.Join(fixture.layout.ManagementPublic, publicName),
		)
		if err != nil {
			t.Fatal(err)
		}
		managementKey, err := parseCanonicalRawED25519(managementPublic)
		if err != nil {
			t.Fatal(err)
		}
		managementWitness := managementBootstrapWitness{
			SchemaVersion:             1,
			Role:                      role,
			RuntimeTarget:             runtimeTarget,
			ConsoleUser:               managementConsoleUser,
			ConsoleUID:                501,
			ConsoleGID:                20,
			RemoteLoginVerified:       true,
			PublicKeyOnlyVerified:     true,
			ForwardingDisabled:        true,
			RootLoginDisabled:         true,
			AllowedUsers:              allowed,
			ManagementKeySHA256:       hashBytes(managementPublic),
			ManagementKeyFingerprint:  ssh.FingerprintSHA256(managementKey),
			AuthorizedKeysSHA256:      repeatHex("a", 64),
			HostKeySHA256:             hashBytes(hostPublic),
			HostKeyFingerprint:        fingerprint,
			RestrictedAccountVerified: restricted,
			PeerHostKeysRegenerated:   regenerated,
			RecoveryRecordSHA256:      repeatHex("b", 64),
			CompletedAt:               now.Unix(),
		}
		managementBytes, err := encodeCanonicalHostJSON(managementWitness)
		if err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{
			externalpeergueststaging.ListenerInventoryName:   inventoryBytes,
			externalpeergueststaging.VMIdentityWitnessName:   identityBytes,
			externalpeergueststaging.SSHHostPublicKeyName:    hostPublic,
			externalpeergueststaging.SSHHostFingerprintName:  []byte(fingerprint + "\n"),
			externalpeergueststaging.SSHBootstrapWitnessName: managementBytes,
		} {
			writeSecureTestFile(t, filepath.Join(root, name), data)
		}
		values = append(values, layerBHostFacts{
			uuid:        uuid,
			mac:         mac,
			ip:          ip,
			fingerprint: fingerprint,
			witness:     append([]byte(nil), identityBytes...),
		})
		clear(managementPublic)
		clear(inventoryBytes)
		clear(managementBytes)
	}
	return values[0], values[1]
}

func addPreparedGuestReviews(t *testing.T, layout Layout) {
	t.Helper()
	configBytes, err := os.ReadFile(filepath.Join(layout.Control, PeerConfigName))
	if err != nil {
		t.Fatal(err)
	}
	expectationBytes, err := os.ReadFile(
		filepath.Join(layout.Control, TicketExpectationName),
	)
	if err != nil {
		t.Fatal(err)
	}
	config, err := externalpeer.DecodePeerSupervisorConfig(configBytes)
	if err != nil {
		t.Fatal(err)
	}
	courierPublic, err := os.ReadFile(
		filepath.Join(layout.PrivateRoot, PublicKeyName),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []struct {
		role externalpeergueststaging.Role
		root string
		vm   externalpeer.SupervisorVMConfig
	}{
		{externalpeergueststaging.ClientRole, layout.GuestClientOutput, config.Client},
		{externalpeergueststaging.PeerRole, layout.GuestPeerOutput, config.Peer},
	} {
		inventoryBytes, err := os.ReadFile(filepath.Join(
			value.root,
			externalpeergueststaging.ListenerInventoryName,
		))
		if err != nil {
			t.Fatal(err)
		}
		inventory, err := externalpeer.DecodeListenerInventory(inventoryBytes)
		if err != nil {
			t.Fatal(err)
		}
		baseline, err := externalpeer.NewListenerBaseline(value.vm, inventory)
		if err != nil {
			t.Fatal(err)
		}
		baselineBytes, err := externalpeer.EncodeListenerBaseline(baseline)
		if err != nil {
			t.Fatal(err)
		}
		review := hostLayerBReviewWitness{
			SchemaVersion:     1,
			Role:              value.role,
			ConfigSHA256:      hashBytes(configBytes),
			ExpectationSHA256: hashBytes(expectationBytes),
			CourierKeySHA256:  hashBytes(courierPublic),
			InventorySHA256:   hashBytes(inventoryBytes),
			BaselineSHA256:    hashBytes(baselineBytes),
		}
		reviewBytes, err := encodeCanonicalHostJSON(review)
		if err != nil {
			t.Fatal(err)
		}
		writeSecureTestFile(
			t,
			filepath.Join(
				value.root,
				externalpeergueststaging.BaselineCandidateName,
			),
			baselineBytes,
		)
		writeSecureTestFile(
			t,
			filepath.Join(
				value.root,
				externalpeergueststaging.ReviewWitnessName,
			),
			reviewBytes,
		)
	}
}

func newLayerBFakeRuntime(
	t *testing.T,
	layout Layout,
	now time.Time,
	client layerBHostFacts,
	peer layerBHostFacts,
) (*layerBFakeExecutor, *fakeRunnerClock, *fakeTartResolver) {
	t.Helper()
	tartPath, err := fixedTartPath(layout)
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeRunnerClock{wall: now}
	return &layerBFakeExecutor{
		tartPath: tartPath,
		clock:    clock,
		client:   client,
		peer:     peer,
	}, clock, &fakeTartResolver{path: tartPath}
}

func assertLayerBCollection(
	t *testing.T,
	layout Layout,
	name string,
	pin bool,
) {
	t.Helper()
	root := filepath.Join(layout.GuestShare, name)
	clientName := filepath.Base(
		externalpeergueststaging.ClientLayerBPrepareInput,
	)
	peerName := filepath.Base(
		externalpeergueststaging.PeerLayerBPrepareInput,
	)
	clientCommand := "kyclash-vm-external-peer-lab-client-prepare-layer-b"
	peerCommand := "kyclash-vm-external-peer-lab-peer-prepare-layer-b"
	if pin {
		clientName = filepath.Base(
			externalpeergueststaging.ClientLayerBPinInput,
		)
		peerName = filepath.Base(
			externalpeergueststaging.PeerLayerBPinInput,
		)
		clientCommand = "kyclash-vm-external-peer-lab-client-pin-layer-b"
		peerCommand = "kyclash-vm-external-peer-lab-peer-pin-layer-b"
	}
	assertDirectoryNames(t, root, []string{clientName, peerName})
	for _, value := range []struct {
		phase   string
		command string
	}{
		{clientName, clientCommand},
		{peerName, peerCommand},
	} {
		names := []string{
			value.command,
			externalpeergueststaging.PeerConfigInputName,
			externalpeergueststaging.TicketExpectationInputName,
			externalpeergueststaging.CourierPublicKeyInputName,
		}
		if pin {
			names = append(
				names,
				externalpeergueststaging.ApprovedListenerBaselineName,
			)
		}
		assertDirectoryNames(t, filepath.Join(root, value.phase), names)
	}
}

func TestLayerBReviewJSONIsCanonical(t *testing.T) {
	t.Parallel()
	value := hostLayerBReviewWitness{
		SchemaVersion:     1,
		Role:              externalpeergueststaging.ClientRole,
		ConfigSHA256:      repeatHex("1", 64),
		ExpectationSHA256: repeatHex("2", 64),
		CourierKeySHA256:  repeatHex("3", 64),
		InventorySHA256:   repeatHex("4", 64),
		BaselineSHA256:    repeatHex("5", 64),
	}
	data, err := encodeCanonicalHostJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded hostLayerBReviewWitness
	if decodeCanonicalHostJSON(data, &decoded) != nil || decoded != value {
		t.Fatal("canonical host review JSON did not round trip")
	}
	var generic map[string]any
	if json.Unmarshal(data, &generic) != nil {
		t.Fatal("canonical review was not JSON")
	}
}
