package externalpeergueststaging

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
	"golang.org/x/crypto/ssh"
)

func TestRuntimeFactsRejectNonVirtualMacNonRootAndWrongRole(t *testing.T) {
	valid := RuntimeFacts{
		GOOS: "darwin", GOARCH: "arm64", EffectiveUID: 0,
		ConsoleUID: 501, ConsoleGID: 20,
		Model:         "VirtualMac2,1",
		Runner:        vmexternalpeerlab.RunnerEnv,
		Confirmation:  vmexternalpeerlab.VMConfirmation,
		RuntimeTarget: vmexternalpeerlab.RuntimeTarget,
		Executable:    "/private/var/tmp/client-stage",
		Identity: VMIdentity{
			Model:                  "VirtualMac2,1",
			Architecture:           "arm64",
			PlatformUUID:           "11111111-1111-4111-8111-111111111111",
			En0MAC:                 "02:00:00:00:00:11",
			En0IPv4:                "192.168.50.11",
			SSHHostPublicKeySHA256: sha256Hex([]byte("host")),
			SSHHostKeyFingerprint:  "SHA256:test-host-key",
		},
	}
	if err := ValidateRuntimeFacts(ClientRole, valid); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*RuntimeFacts){
		"host-model": func(value *RuntimeFacts) {
			value.Model = "Mac15,7"
		},
		"non-root": func(value *RuntimeFacts) {
			value.EffectiveUID = 501
		},
		"wrong-architecture": func(value *RuntimeFacts) {
			value.GOARCH = "amd64"
		},
		"wrong-target": func(value *RuntimeFacts) {
			value.RuntimeTarget = vmexternalpeerlab.PeerRuntimeTarget
		},
		"relative-executable": func(value *RuntimeFacts) {
			value.Executable = "client-stage"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := ValidateRuntimeFacts(ClientRole, candidate); err == nil {
				t.Fatal("unsafe runtime facts were accepted")
			}
		})
	}
	peer := valid
	peer.RuntimeTarget = vmexternalpeerlab.PeerRuntimeTarget
	if err := ValidateRuntimeFacts(PeerRole, peer); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ClientRole, LayerAStage, []string{"unexpected"}); err == nil {
		t.Fatal("guest staging command accepted an argument")
	}
}

func TestStableInputRejectsSymlinkModeAndReplacement(t *testing.T) {
	root := t.TempDir()
	var err error
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := currentIdentity(t)
	inputPath := filepath.Join(root, "input")
	mkdir(t, inputPath, inputDirectoryMode)
	writeFile(t, filepath.Join(inputPath, "value"), []byte("safe"), inputFileMode)
	input, err := openStableDirectory(
		inputPath, uid, gid, inputDirectoryMode,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer input.close()
	if _, err := input.readStableFile(
		"value", inputFileMode, 16, func(string) {
			original := filepath.Join(inputPath, "value")
			replaced := filepath.Join(inputPath, "replaced")
			if err := os.Rename(original, replaced); err != nil {
				t.Fatal(err)
			}
			writeFile(t, original, []byte("evil"), inputFileMode)
		},
	); err == nil {
		t.Fatal("replacement during stable read was accepted")
	}

	symlinkInput := filepath.Join(root, "symlink-input")
	mkdir(t, symlinkInput, inputDirectoryMode)
	if err := os.Symlink("/dev/null", filepath.Join(symlinkInput, "value")); err != nil {
		t.Fatal(err)
	}
	symlinkDirectory, err := openStableDirectory(
		symlinkInput, uid, gid, inputDirectoryMode,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer symlinkDirectory.close()
	if _, err := symlinkDirectory.readStableFile(
		"value", inputFileMode, 16, nil,
	); err == nil {
		t.Fatal("symlinked input was accepted")
	}

	modeInput := filepath.Join(root, "mode-input")
	mkdir(t, modeInput, inputDirectoryMode)
	writeFile(t, filepath.Join(modeInput, "value"), []byte("safe"), 0o644)
	modeDirectory, err := openStableDirectory(
		modeInput, uid, gid, inputDirectoryMode,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer modeDirectory.close()
	if _, err := modeDirectory.readStableFile(
		"value", inputFileMode, 16, nil,
	); err == nil {
		t.Fatal("over-broad input mode was accepted")
	}

	linkInput := filepath.Join(root, "link-input")
	mkdir(t, linkInput, inputDirectoryMode)
	writeFile(t, filepath.Join(linkInput, "value"), []byte("safe"), inputFileMode)
	if err := os.Link(
		filepath.Join(linkInput, "value"),
		filepath.Join(linkInput, "second-link"),
	); err != nil {
		t.Fatal(err)
	}
	linkDirectory, err := openStableDirectory(
		linkInput, uid, gid, inputDirectoryMode,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer linkDirectory.close()
	if _, err := linkDirectory.readStableFile(
		"value", inputFileMode, 16, nil,
	); err == nil {
		t.Fatal("hard-linked input was accepted")
	}
}

func TestClientThreePhaseStagingRequiresExplicitBaselineApproval(t *testing.T) {
	fixture := newWorkflowFixture(t, ClientRole)
	layerA := fixture.newRunner(LayerAStage)
	result, err := layerA.run()
	if err != nil {
		t.Fatal(err)
	}
	if result.ReviewPath != filepath.Join(
		fixture.layout.ClientReview, ListenerInventoryName,
	) {
		t.Fatalf("unexpected review output: %#v", result)
	}
	recoveredLayerA, err := layerA.run()
	if err != nil || recoveredLayerA != result {
		t.Fatal("repeated Layer-A staging did not recover idempotently")
	}
	if !pathAbsent(filepath.Join(
		fixture.layout.Configuration,
		PeerConfigInputName,
	)) {
		t.Fatal("Layer A installed Layer-B configuration")
	}
	fixture.runSSHBootstrap(t)

	configBytes := fixture.configBytes(t)
	expectationBytes := fixture.expectationBytes(t, configBytes)
	fixture.writeLayerBInput(
		t, LayerBPrepare, configBytes, expectationBytes, nil,
	)
	prepare := fixture.newRunner(LayerBPrepare)
	prepared, err := prepare.run()
	if err != nil {
		t.Fatal(err)
	}
	candidateBytes, err := os.ReadFile(prepared.ReviewPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := externalpeer.DecodeListenerBaseline(candidateBytes); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(candidateBytes, []byte(`"launchd_pid1":false`)) {
		t.Fatal("baseline candidate omitted the explicit launchd PID-1 review fact")
	}
	if !pathAbsent(filepath.Join(
		fixture.layout.ClientStageRoot,
		filepath.Base(vmexternalpeerlab.AppManifestPath),
	)) {
		t.Fatal("review preparation silently pinned a runtime manifest")
	}

	fixture.writeLayerBInput(
		t, LayerBPin, configBytes, expectationBytes, candidateBytes,
	)
	pin := fixture.newRunner(LayerBPin)
	if _, err := pin.run(); err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(
		fixture.layout.ClientStageRoot,
		filepath.Base(vmexternalpeerlab.AppManifestPath),
	))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := vmexternalpeerlab.DecodeAppManifestV2(
		bytes.NewReader(manifestBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ClientListenerBaselineSHA256 != sha256Hex(candidateBytes) ||
		manifest.ExecutablePath != vmexternalpeerlab.AppExecutablePath ||
		!validSHA256(manifest.AppTreeSHA256) ||
		!validSHA256(manifest.AppTreeManifestSHA256) {
		t.Fatalf("App manifest did not pin approved bytes: %#v", manifest)
	}
	if recovered, err := pin.run(); err != nil ||
		recovered.ReviewSHA != sha256Hex(candidateBytes) {
		t.Fatal("repeated Layer-B pin did not recover idempotently")
	}
}

func TestClientLayerARejectsSymlinkInsideAppBundle(t *testing.T) {
	fixture := newWorkflowFixture(t, ClientRole)
	icon := filepath.Join(
		fixture.layout.input(ClientRole, LayerAStage),
		AppInputName,
		"Contents",
		"Resources",
		"icon.icns",
	)
	if err := os.Remove(icon); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", icon); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.newRunner(LayerAStage).run(); err == nil {
		t.Fatal("symlink inside App bundle was staged")
	}
}

func TestClientLayerARejectsCanonicalManifestTreeMismatch(t *testing.T) {
	fixture := newWorkflowFixture(t, ClientRole)
	path := filepath.Join(
		fixture.layout.input(ClientRole, LayerAStage),
		AppTreeManifestInputName,
	)
	manifest, err := decodeAppTreeManifest(readFile(t, path))
	if err != nil {
		t.Fatal(err)
	}
	manifest.TreeSHA256 = strings.Repeat("0", 64)
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeFileReplacement(
		t,
		path,
		append(encoded, '\n'),
		inputFileMode,
	)
	if _, err := fixture.newRunner(LayerAStage).run(); err == nil {
		t.Fatal("canonical manifest with mismatched entries digest was accepted")
	}
}

func TestSSHBootstrapRequiresLayerAAndCanonicalRoleKey(t *testing.T) {
	fixture := newWorkflowFixture(t, ClientRole)
	input := fixture.layout.input(ClientRole, LayerASSHBootstrap)
	mkdir(t, input, inputDirectoryMode)
	writeFile(
		t,
		filepath.Join(input, commandName(ClientRole, LayerASSHBootstrap)),
		fakeMachO("ssh-bootstrap"),
		inputExecutableMode,
	)
	writeFile(
		t,
		filepath.Join(input, ClientManagementPublicKeyName),
		fixture.managementKey,
		inputFileMode,
	)
	if _, err := fixture.newRunner(LayerASSHBootstrap).run(); err == nil {
		t.Fatal("SSH bootstrap ran before the Layer-A listener review existed")
	}
	if _, err := fixture.newRunner(LayerAStage).run(); err != nil {
		t.Fatal(err)
	}
	authorizedText := ssh.MarshalAuthorizedKey(
		mustCanonicalSSHKey(t, fixture.managementKey),
	)
	writeFileReplacement(
		t,
		filepath.Join(input, ClientManagementPublicKeyName),
		authorizedText,
		inputFileMode,
	)
	if _, err := fixture.newRunner(LayerASSHBootstrap).run(); err == nil {
		t.Fatal("authorized_keys text was accepted instead of canonical raw bytes")
	}
}

func TestPeerThreePhaseStagingProducesStrictManifest(t *testing.T) {
	fixture := newWorkflowFixture(t, PeerRole)
	if _, err := fixture.newRunner(LayerAStage).run(); err != nil {
		t.Fatal(err)
	}
	fixture.runSSHBootstrap(t)
	configBytes := fixture.configBytes(t)
	expectationBytes := fixture.expectationBytes(t, configBytes)
	fixture.writeLayerBInput(
		t, LayerBPrepare, configBytes, expectationBytes, nil,
	)
	prepared, err := fixture.newRunner(LayerBPrepare).run()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := os.ReadFile(prepared.ReviewPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.writeLayerBInput(
		t, LayerBPin, configBytes, expectationBytes, candidate,
	)
	if _, err := fixture.newRunner(LayerBPin).run(); err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(
		fixture.layout.Configuration,
		filepath.Base(externalpeer.PeerStagingManifestPath),
	))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := externalpeer.DecodePeerStagingManifest(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.PeerChild.Device == 0 ||
		manifest.PeerChild.Inode == 0 ||
		manifest.PeerChild.Size == 0 ||
		manifest.PeerListenerBaseline.SHA256 != sha256Hex(candidate) {
		t.Fatalf("peer manifest lacks stable identity pins: %#v", manifest)
	}
}

func TestPrepareRefusesInputReplacementBeforeCommit(t *testing.T) {
	fixture := newWorkflowFixture(t, PeerRole)
	if _, err := fixture.newRunner(LayerAStage).run(); err != nil {
		t.Fatal(err)
	}
	fixture.runSSHBootstrap(t)
	configBytes := fixture.configBytes(t)
	expectationBytes := fixture.expectationBytes(t, configBytes)
	inputPath := fixture.writeLayerBInput(
		t, LayerBPrepare, configBytes, expectationBytes, nil,
	)
	prepare := fixture.newRunner(LayerBPrepare)
	prepare.hooks.beforeCommit = func() {
		path := filepath.Join(inputPath, PeerConfigInputName)
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		writeFile(t, path, configBytes, inputFileMode)
	}
	if _, err := prepare.run(); err == nil {
		t.Fatal("input replacement between review and commit was accepted")
	}
	if !pathAbsent(filepath.Join(
		fixture.layout.PeerReview, BaselineCandidateName,
	)) {
		t.Fatal("failed preparation published a baseline candidate")
	}
}

func TestCommittedPhaseTransactionRecoversAfterPublishFault(t *testing.T) {
	fixture := newWorkflowFixture(t, PeerRole)
	injected := errors.New("injected publish interruption")
	faulted := fixture.newRunner(LayerAStage)
	faulted.hooks.afterMutation = func(label string) error {
		if strings.HasPrefix(label, "publish:") {
			return injected
		}
		return nil
	}
	if _, err := faulted.run(); !errors.Is(err, injected) {
		t.Fatalf("publish fault was not surfaced: %v", err)
	}
	state := filepath.Join(
		fixture.layout.TransactionRoot,
		string(PeerRole)+"-"+string(LayerAStage)+"-v1",
	)
	if pathAbsent(filepath.Join(state, phaseTransactionJournalName)) ||
		pathAbsent(fixture.layout.PeerSupervisor) {
		t.Fatal("durable journal did not precede the interrupted publication")
	}
	recovered, err := fixture.newRunner(LayerAStage).run()
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Role != PeerRole ||
		recovered.Phase != LayerAStage ||
		pathAbsent(fixture.layout.PeerChild) ||
		pathAbsent(fixture.layout.ListenerAuditor) ||
		pathAbsent(fixture.layout.ForcedCommand) ||
		pathAbsent(filepath.Join(
			fixture.layout.PeerReview,
			ListenerInventoryName,
		)) ||
		pathAbsent(filepath.Join(state, phaseTransactionCompleteName)) {
		t.Fatal("committed transaction did not roll forward exactly")
	}
}

func TestUnjournaledPhaseTransactionIsSafelyRecreated(t *testing.T) {
	fixture := newWorkflowFixture(t, PeerRole)
	commandSHA := sha256Hex([]byte("fixed-command"))
	injected := errors.New("injected pre-journal interruption")
	transaction, recovered, err := beginPhaseTransaction(
		fixture.layout,
		PeerRole,
		LayerBPrepare,
		fixture.facts.RuntimeTarget,
		commandSHA,
		fixture.facts.Identity,
		fixture.uid,
		fixture.gid,
		func(label string) error {
			if strings.HasPrefix(label, "stage-file:") {
				return injected
			}
			return nil
		},
	)
	if err != nil || recovered != nil {
		t.Fatal("could not begin interrupted transaction fixture")
	}
	outputParent := filepath.Join(fixture.root, "transaction-output")
	mkdir(t, outputParent, 0o755)
	destination := filepath.Join(outputParent, "durable-output")
	if _, err := transaction.stageFile(
		destination,
		[]byte("durable"),
		0o600,
		0o755,
	); !errors.Is(err, injected) {
		t.Fatalf("pre-journal fault was not surfaced: %v", err)
	}
	restarted, recovered, err := beginPhaseTransaction(
		fixture.layout,
		PeerRole,
		LayerBPrepare,
		fixture.facts.RuntimeTarget,
		commandSHA,
		fixture.facts.Identity,
		fixture.uid,
		fixture.gid,
		nil,
	)
	if err != nil || recovered != nil {
		t.Fatal("unjournaled transaction did not restart cleanly")
	}
	entries, err := os.ReadDir(restarted.pending)
	if err != nil || len(entries) != 0 {
		t.Fatal("stale pre-journal pending output survived recovery")
	}
	if _, err := restarted.stageFile(
		destination,
		[]byte("durable"),
		0o600,
		0o755,
	); err != nil {
		t.Fatal(err)
	}
	result := Result{
		Role:       PeerRole,
		Phase:      LayerBPrepare,
		ReviewPath: destination,
		ReviewSHA:  sha256Hex([]byte("durable")),
	}
	if _, err := restarted.commit(
		result,
		fixture.facts.Identity,
	); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, destination)) != "durable" {
		t.Fatal("restarted transaction published different bytes")
	}
}

func TestLayerARefusesIdentityDriftBeforePublication(t *testing.T) {
	cases := map[string]func(*VMIdentity){
		"platform-uuid": func(value *VMIdentity) {
			value.PlatformUUID =
				"33333333-3333-4333-8333-333333333333"
		},
		"en0-mac": func(value *VMIdentity) {
			value.En0MAC = "02:00:00:00:00:33"
		},
		"en0-ip": func(value *VMIdentity) {
			value.En0IPv4 = "192.168.50.33"
		},
		"ssh-host-fingerprint": func(value *VMIdentity) {
			value.SSHHostKeyFingerprint = "SHA256:changed-host-key"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newWorkflowFixture(t, PeerRole)
			runner := fixture.newRunner(LayerAStage)
			calls := 0
			runner.identity = func(context.Context) (VMIdentity, error) {
				calls++
				current := fixture.facts.Identity
				if calls > 1 {
					mutate(&current)
				}
				return current, nil
			}
			if _, err := runner.run(); err == nil {
				t.Fatal("identity drift was accepted")
			}
			for _, path := range []string{
				fixture.layout.PeerSupervisor,
				fixture.layout.PeerChild,
				fixture.layout.ListenerAuditor,
				fixture.layout.ForcedCommand,
				fixture.layout.PeerReview,
			} {
				if !pathAbsent(path) {
					t.Fatalf("identity drift published %s", path)
				}
			}
		})
	}
}

func TestLayerBRejectsAppTreeResourceAndExtraFileTamper(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string){
		"resource": func(t *testing.T, app string) {
			writeFileReplacement(
				t,
				filepath.Join(app, "Contents", "Resources", "icon.icns"),
				[]byte("evil"),
				0o644,
			)
		},
		"extra-file": func(t *testing.T, app string) {
			writeFile(
				t,
				filepath.Join(app, "Contents", "extra"),
				[]byte("extra"),
				0o644,
			)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newWorkflowFixture(t, ClientRole)
			if _, err := fixture.newRunner(LayerAStage).run(); err != nil {
				t.Fatal(err)
			}
			fixture.runSSHBootstrap(t)
			app := filepath.Join(
				fixture.layout.Applications,
				AppInputName,
			)
			mutate(t, app)
			config := fixture.configBytes(t)
			expectation := fixture.expectationBytes(t, config)
			fixture.writeLayerBInput(
				t,
				LayerBPrepare,
				config,
				expectation,
				nil,
			)
			if _, err := fixture.newRunner(LayerBPrepare).run(); err == nil {
				t.Fatal("tampered installed App tree passed Layer B")
			}
		})
	}
}

type workflowFixture struct {
	role          Role
	root          string
	layout        Layout
	uid           uint32
	gid           uint32
	facts         RuntimeFacts
	inventory     externalpeer.ListenerInventory
	key           []byte
	managementKey []byte
	hostKey       []byte
}

func newWorkflowFixture(t *testing.T, role Role) *workflowFixture {
	t.Helper()
	root := t.TempDir()
	var err error
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := currentIdentity(t)
	for _, path := range []string{
		filepath.Join(root, "input"),
		filepath.Join(root, "Applications"),
		filepath.Join(root, "etc"),
		filepath.Join(root, "Library"),
		filepath.Join(root, "usr"),
		filepath.Join(root, "usr", "local"),
	} {
		mkdir(t, path, 0o755)
	}
	layout := Layout{
		InputBase:       filepath.Join(root, "input"),
		ClientReview:    filepath.Join(root, "client-review"),
		PeerReview:      filepath.Join(root, "peer-review"),
		ClientStageRoot: filepath.Join(root, "client-stage"),
		Applications:    filepath.Join(root, "Applications"),
		Configuration:   filepath.Join(root, "etc", "external-peer"),
		PeerSupervisor: filepath.Join(
			root, "Library", "PrivilegedHelperTools", "peer-supervisor",
		),
		PeerChild: filepath.Join(
			root, "usr", "local", "libexec", "peer-child",
		),
		ListenerAuditor: filepath.Join(
			root, "usr", "local", "libexec", "listener-auditor",
		),
		ForcedCommand: filepath.Join(
			root, "usr", "local", "libexec", "forced-command",
		),
		TransactionRoot: filepath.Join(root, "transactions"),
	}
	target := vmexternalpeerlab.RuntimeTarget
	if role == PeerRole {
		target = vmexternalpeerlab.PeerRuntimeTarget
	}
	fixture := &workflowFixture{
		role: role, root: root, layout: layout, uid: uid, gid: gid,
		facts: RuntimeFacts{
			GOOS: "darwin", GOARCH: "arm64", EffectiveUID: 0,
			ConsoleUID: uid, ConsoleGID: gid,
			Model:         "VirtualMac2,1",
			Runner:        vmexternalpeerlab.RunnerEnv,
			Confirmation:  vmexternalpeerlab.VMConfirmation,
			RuntimeTarget: target,
		},
		inventory: externalpeer.ListenerInventory{
			SchemaVersion: externalpeer.SchemaVersion,
			CollectedAt:   time.Now().UTC().Unix(),
			Listeners: []externalpeer.ListenerRecord{{
				Protocol: "tcp", BindAddress: "0.0.0.0", Port: 22,
				PID: 100, StartIdentity: "1710000000:1",
				UID: 0, Command: "sshd",
				ExecutablePath:   "/usr/sbin/sshd",
				ExecutableSHA256: externalpeer.HashHex([]byte("sshd")),
				CodeSignature:    "apple-anchor;identifier=com.openssh.sshd;team=APPLE;authority=Apple",
				LaunchdLabel:     "com.openssh.sshd",
			}},
		},
		key: make([]byte, ed25519.PublicKeySize),
	}
	for index := range fixture.key {
		fixture.key[index] = byte(index + 1)
	}
	managementPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x41}, ed25519.SeedSize),
	)
	managementSSH, err := ssh.NewPublicKey(managementPrivate.Public())
	if err != nil {
		t.Fatal(err)
	}
	fixture.managementKey = managementSSH.Marshal()
	hostPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x52}, ed25519.SeedSize),
	)
	hostSSH, err := ssh.NewPublicKey(hostPrivate.Public())
	if err != nil {
		t.Fatal(err)
	}
	fixture.hostKey = hostSSH.Marshal()
	fixture.facts.Identity = VMIdentity{
		Model:                  fixture.facts.Model,
		Architecture:           "arm64",
		PlatformUUID:           "11111111-1111-4111-8111-111111111111",
		En0MAC:                 "02:00:00:00:00:11",
		En0IPv4:                "192.168.50.11",
		SSHHostPublicKeySHA256: sha256Hex(fixture.hostKey),
		SSHHostKeyFingerprint:  ssh.FingerprintSHA256(hostSSH),
	}
	if role == PeerRole {
		fixture.facts.Identity.PlatformUUID =
			"22222222-2222-4222-8222-222222222222"
		fixture.facts.Identity.En0MAC = "02:00:00:00:00:22"
		fixture.facts.Identity.En0IPv4 = "192.168.50.22"
	}
	fixture.writeLayerAInput(t)
	return fixture
}

func (fixture *workflowFixture) newRunner(phase Phase) *runner {
	result := &runner{
		role: fixture.role, phase: phase,
		layout: fixture.layout, facts: fixture.facts,
		rootUID: fixture.uid, rootGID: fixture.gid,
		collect: func(context.Context) (externalpeer.ListenerInventory, error) {
			return fixture.inventory, nil
		},
		identity: func(context.Context) (VMIdentity, error) {
			return fixture.facts.Identity, nil
		},
		bootstrap: SSHBootstrapperFunc(
			func(
				_ context.Context,
				request SSHBootstrapRequest,
			) (SSHBootstrapResult, error) {
				host, err := parseCanonicalRawED25519(fixture.hostKey)
				if err != nil {
					return SSHBootstrapResult{}, err
				}
				allowed := []string{"supen"}
				restricted := false
				regenerated := false
				if fixture.role == PeerRole {
					allowed = append(allowed, restrictedSSHAccount)
					restricted = true
					regenerated = true
				}
				management, err := parseCanonicalRawED25519(
					request.ManagementPublicKey,
				)
				if err != nil {
					return SSHBootstrapResult{}, err
				}
				authorized := ssh.MarshalAuthorizedKey(management)
				return SSHBootstrapResult{
					HostPublicKey: append([]byte(nil), fixture.hostKey...),
					Evidence: SSHBootstrapEvidence{
						SchemaVersion:             1,
						Role:                      fixture.role,
						RuntimeTarget:             request.RuntimeTarget,
						ConsoleUser:               "supen",
						ConsoleUID:                request.ConsoleUID,
						ConsoleGID:                request.ConsoleGID,
						RemoteLoginVerified:       true,
						PublicKeyOnlyVerified:     true,
						ForwardingDisabled:        true,
						RootLoginDisabled:         true,
						AllowedUsers:              allowed,
						ManagementKeySHA256:       request.ManagementKeySHA256,
						ManagementKeyFingerprint:  request.ManagementKeyFingerprint,
						AuthorizedKeysSHA256:      sha256Hex(authorized),
						HostKeySHA256:             sha256Hex(fixture.hostKey),
						HostKeyFingerprint:        ssh.FingerprintSHA256(host),
						RestrictedAccountVerified: restricted,
						PeerHostKeysRegenerated:   regenerated,
						RecoveryRecordSHA256:      sha256Hex([]byte("recovery")),
						CompletedAt:               time.Now().UTC().Unix(),
					},
				}, nil
			},
		),
	}
	result.facts.Executable = filepath.Join(
		fixture.layout.input(fixture.role, phase),
		commandName(fixture.role, phase),
	)
	return result
}

type SSHBootstrapperFunc func(
	context.Context,
	SSHBootstrapRequest,
) (SSHBootstrapResult, error)

func (function SSHBootstrapperFunc) Bootstrap(
	ctx context.Context,
	request SSHBootstrapRequest,
) (SSHBootstrapResult, error) {
	return function(ctx, request)
}

func (fixture *workflowFixture) runSSHBootstrap(t *testing.T) {
	t.Helper()
	input := fixture.layout.input(fixture.role, LayerASSHBootstrap)
	mkdir(t, input, inputDirectoryMode)
	writeFile(
		t,
		filepath.Join(input, commandName(fixture.role, LayerASSHBootstrap)),
		fakeMachO("ssh-bootstrap"),
		inputExecutableMode,
	)
	keyName := ClientManagementPublicKeyName
	if fixture.role == PeerRole {
		keyName = PeerManagementPublicKeyName
	}
	writeFile(
		t,
		filepath.Join(input, keyName),
		fixture.managementKey,
		inputFileMode,
	)
	result, err := fixture.newRunner(LayerASSHBootstrap).run()
	if err != nil {
		t.Fatal(err)
	}
	output := formatResult(result)
	if !bytes.Contains(
		[]byte(output),
		[]byte("layer_a_ssh_bootstrap=true"),
	) ||
		!bytes.Contains([]byte(output), []byte(SSHHostPublicKeyName)) ||
		!bytes.Contains([]byte(output), []byte(SSHHostFingerprintName)) {
		t.Fatal("SSH bootstrap result omitted its public review paths")
	}
	for _, name := range sshBootstrapReviewNames()[1:] {
		if pathAbsent(filepath.Join(fixture.layout.review(fixture.role), name)) {
			t.Fatalf("SSH bootstrap omitted %s", name)
		}
	}
}

func (fixture *workflowFixture) writeLayerAInput(t *testing.T) {
	t.Helper()
	input := fixture.layout.input(fixture.role, LayerAStage)
	mkdir(t, input, inputDirectoryMode)
	writeFile(
		t,
		filepath.Join(input, commandName(fixture.role, LayerAStage)),
		fakeMachO("command"),
		inputExecutableMode,
	)
	if fixture.role == PeerRole {
		for _, name := range []string{
			"kyclash-vm-external-peer-lab-peer-root-supervisor",
			"kyclash-vm-external-peer-lab-peer",
			"kyclash-vm-external-peer-lab-listener-auditor",
			"kyclash-vm-external-peer-lab-forced-command",
		} {
			writeFile(
				t, filepath.Join(input, name),
				fakeMachO(name), inputExecutableMode,
			)
		}
		return
	}
	for _, name := range []string{
		"kyclash-vm-external-peer-lab-supervisor",
		"kyclash-vm-external-peer-lab-harness",
		MihomoInputName,
	} {
		writeFile(
			t, filepath.Join(input, name),
			fakeMachO(name), inputExecutableMode,
		)
	}
	config, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "macos", "route-helper",
		"vm-external-peer-lab-mihomo-config.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(
		t, filepath.Join(input, MihomoConfigInputName),
		config, inputFileMode,
	)
	app := filepath.Join(input, AppInputName)
	mkdir(t, app, inputDirectoryMode)
	mkdir(t, filepath.Join(app, "Contents"), 0o755)
	mkdir(t, filepath.Join(app, "Contents", "MacOS"), 0o755)
	mkdir(t, filepath.Join(app, "Contents", "Resources"), 0o755)
	writeFile(
		t, filepath.Join(app, "Contents", "Info.plist"),
		[]byte("<plist></plist>\n"), 0o644,
	)
	writeFile(
		t, filepath.Join(app, "Contents", "MacOS", "clash-verge"),
		fakeMachO("app"), 0o755,
	)
	writeFile(
		t, filepath.Join(app, "Contents", "Resources", "icon.icns"),
		[]byte("icon"), 0o644,
	)
	appDirectory, err := openStableDirectory(
		app,
		fixture.uid,
		fixture.gid,
		inputDirectoryMode,
	)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := collectStableAppTree(appDirectory)
	closeErr := appDirectory.close()
	if err != nil || closeErr != nil {
		t.Fatal(ErrGuestStaging)
	}
	entries[0].Mode = "0755"
	encodedEntries, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	var executable appTreeEntry
	for _, entry := range entries {
		if entry.RelativePath == "Contents/MacOS/clash-verge" {
			executable = entry
			break
		}
	}
	if executable.SHA256 == nil {
		t.Fatal("fixture App executable was not collected")
	}
	manifest := appTreeManifest{
		SchemaVersion: 1,
		AppName:       AppInputName,
		Source: appBuildSource{
			Commit:       strings.Repeat("a", 40),
			Dirty:        true,
			StatusSHA256: strings.Repeat("b", 64),
			TreeSHA256:   strings.Repeat("c", 64),
			FileCount:    len(entries),
		},
		TreeSHA256: hashHex(encodedEntries),
		InfoPlist: appInfoPlistRecord{
			RelativePath:     "Contents/Info.plist",
			BundleIdentifier: "net.kysion.kyclash",
			ShortVersion:     "2.5.3",
			BundleVersion:    "2.5.3",
			BundleExecutable: "clash-verge",
		},
		MainExecutable: appExecutableRecord{
			RelativePath: executable.RelativePath,
			Mode:         executable.Mode,
			ByteLength:   executable.ByteLength,
			SHA256:       *executable.SHA256,
		},
		Entries: entries,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(
		t,
		filepath.Join(input, AppTreeManifestInputName),
		append(manifestBytes, '\n'),
		inputFileMode,
	)
}

func (fixture *workflowFixture) configBytes(t *testing.T) []byte {
	t.Helper()
	config := externalpeer.PeerSupervisorConfig{
		SchemaVersion: externalpeer.SchemaVersion,
		ConsoleUID:    fixture.uid,
		ConsoleGID:    fixture.gid,
		PeerChildUID:  restrictedSSHUID,
		PeerChildGID:  restrictedSSHGID,
		Client: externalpeer.SupervisorVMConfig{
			Role: "client", VMName: externalpeer.ClientVMName,
			PlatformUUID:       "11111111-1111-4111-8111-111111111111",
			SSHHostFingerprint: "SHA256:client-host-key",
			MAC:                "02:00:00:00:00:11", IPv4: "192.168.50.11",
		},
		Peer: externalpeer.SupervisorVMConfig{
			Role: "peer", VMName: externalpeer.PeerVMName,
			PlatformUUID:       "22222222-2222-4222-8222-222222222222",
			SSHHostFingerprint: "SHA256:peer-host-key",
			MAC:                "02:00:00:00:00:22", IPv4: "192.168.50.22",
		},
	}
	roleConfig := &config.Client
	if fixture.role == PeerRole {
		roleConfig = &config.Peer
	}
	roleConfig.PlatformUUID = fixture.facts.Identity.PlatformUUID
	roleConfig.SSHHostFingerprint =
		fixture.facts.Identity.SSHHostKeyFingerprint
	roleConfig.MAC = fixture.facts.Identity.En0MAC
	roleConfig.IPv4 = fixture.facts.Identity.En0IPv4
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := externalpeer.DecodePeerSupervisorConfig(encoded); err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func (fixture *workflowFixture) expectationBytes(
	t *testing.T,
	config []byte,
) []byte {
	t.Helper()
	files := make(map[string][]byte)
	if fixture.role == ClientRole {
		files["app"] = readFile(t, filepath.Join(
			fixture.layout.Applications,
			AppInputName, "Contents", "MacOS", "clash-verge",
		))
		files["client-supervisor"] = readFile(t, filepath.Join(
			fixture.layout.ClientStageRoot,
			"kyclash-vm-external-peer-lab-supervisor",
		))
		files["client-harness"] = readFile(t, filepath.Join(
			fixture.layout.ClientStageRoot,
			"kyclash-vm-external-peer-lab-harness",
		))
	} else {
		files["peer-supervisor"] = readFile(t, fixture.layout.PeerSupervisor)
		files["peer-child"] = readFile(t, fixture.layout.PeerChild)
		files["listener-auditor"] = readFile(t, fixture.layout.ListenerAuditor)
		files["forced-command-helper"] = readFile(t, fixture.layout.ForcedCommand)
	}
	files["peer-config"] = config
	expectation := externalpeer.RunTicketExpectation{
		SchemaVersion: externalpeer.SchemaVersion,
		Files: make([]externalpeer.ArtifactDigest, 0, len(
			externalpeer.RunTicketArtifactNames,
		)),
	}
	for _, name := range externalpeer.RunTicketArtifactNames {
		data, ok := files[name]
		if !ok {
			data = []byte("remote-" + name)
		}
		expectation.Files = append(
			expectation.Files,
			externalpeer.ArtifactDigest{
				Name:   name,
				Length: uint64(len(data)),
				SHA256: sha256Hex(data),
			},
		)
	}
	encoded, err := json.Marshal(expectation)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func (fixture *workflowFixture) writeLayerBInput(
	t *testing.T,
	phase Phase,
	config []byte,
	expectation []byte,
	approved []byte,
) string {
	t.Helper()
	path := fixture.layout.input(fixture.role, phase)
	mkdir(t, path, inputDirectoryMode)
	writeFile(
		t, filepath.Join(path, commandName(fixture.role, phase)),
		fakeMachO("phase-command"), inputExecutableMode,
	)
	writeFile(
		t, filepath.Join(path, PeerConfigInputName),
		config, inputFileMode,
	)
	writeFile(
		t, filepath.Join(path, TicketExpectationInputName),
		expectation, inputFileMode,
	)
	writeFile(
		t, filepath.Join(path, CourierPublicKeyInputName),
		fixture.key, inputFileMode,
	)
	if phase == LayerBPin {
		writeFile(
			t, filepath.Join(path, ApprovedListenerBaselineName),
			approved, inputFileMode,
		)
	}
	return path
}

func currentIdentity(t *testing.T) (uint32, uint32) {
	t.Helper()
	return uint32(os.Getuid()), uint32(os.Getgid())
}

func mkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func writeFile(
	t *testing.T,
	path string,
	data []byte,
	mode os.FileMode,
) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func writeFileReplacement(
	t *testing.T,
	path string,
	data []byte,
	mode os.FileMode,
) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, data, mode)
}

func mustCanonicalSSHKey(t *testing.T, raw []byte) ssh.PublicKey {
	t.Helper()
	key, err := parseCanonicalRawED25519(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func fakeMachO(label string) []byte {
	result := make([]byte, 32, 32+len(label))
	copy(result[:], []byte{
		0xcf, 0xfa, 0xed, 0xfe,
		0x0c, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00,
	})
	return append(result, []byte(label)...)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return fmtHex(digest[:])
}

func fmtHex(data []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for index, value := range data {
		result[index*2] = digits[value>>4]
		result[index*2+1] = digits[value&0x0f]
	}
	return string(result)
}
