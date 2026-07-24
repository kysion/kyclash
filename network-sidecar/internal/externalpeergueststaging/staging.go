package externalpeergueststaging

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
	"golang.org/x/crypto/ssh"
)

type ListenerCollector func(context.Context) (externalpeer.ListenerInventory, error)

type runner struct {
	role            Role
	phase           Phase
	layout          Layout
	facts           RuntimeFacts
	rootUID         uint32
	rootGID         uint32
	collect         ListenerCollector
	identity        VMIdentityCollector
	bootstrap       SSHBootstrapper
	hooks           readHooks
	currentIdentity VMIdentity
	commandSHA256   string
	transaction     *phaseTransaction
}

type Result struct {
	Role       Role
	Phase      Phase
	ReviewPath string
	ReviewSHA  string
}

type layerBInputs struct {
	configBytes      stableBlob
	expectationBytes stableBlob
	courierPublicKey stableBlob
	config           externalpeer.PeerSupervisorConfig
	expectation      externalpeer.RunTicketExpectation
}

type reviewWitness struct {
	SchemaVersion     uint8  `json:"schema_version"`
	Role              Role   `json:"role"`
	ConfigSHA256      string `json:"config_sha256"`
	ExpectationSHA256 string `json:"expectation_sha256"`
	CourierKeySHA256  string `json:"courier_public_key_sha256"`
	InventorySHA256   string `json:"listener_inventory_sha256"`
	BaselineSHA256    string `json:"listener_baseline_sha256"`
}

func Run(role Role, phase Phase, arguments []string) (Result, error) {
	if len(arguments) != 0 {
		return Result{}, ErrGuestStaging
	}
	facts, err := productionRuntimeFacts()
	if err != nil {
		return Result{}, err
	}
	executor := runner{
		role: role, phase: phase,
		layout: ProductionLayout(), facts: facts,
		rootUID: 0, rootGID: 0,
		collect:   externalpeer.CollectListenerInventory,
		identity:  collectProductionVMIdentity,
		bootstrap: productionSSHBootstrapper{},
	}
	return executor.run()
}

func (value *runner) run() (Result, error) {
	if value == nil ||
		(value.role != ClientRole && value.role != PeerRole) ||
		(value.phase != LayerAStage &&
			value.phase != LayerASSHBootstrap &&
			value.phase != LayerBPrepare &&
			value.phase != LayerBPin) ||
		(value.phase == LayerASSHBootstrap && value.bootstrap == nil) ||
		(value.phase != LayerASSHBootstrap && value.collect == nil) ||
		value.identity == nil ||
		ValidateRuntimeFacts(value.role, value.facts) != nil {
		return Result{}, ErrGuestStaging
	}
	inputPath := value.layout.input(value.role, value.phase)
	if value.facts.Executable != filepath.Join(
		inputPath, commandName(value.role, value.phase),
	) {
		return Result{}, ErrGuestStaging
	}
	input, err := openStableDirectory(
		inputPath,
		value.facts.ConsoleUID,
		value.facts.ConsoleGID,
		inputDirectoryMode,
	)
	if err != nil {
		return Result{}, err
	}
	defer input.close()
	if input.requireExactNames(
		expectedInputNames(value.role, value.phase),
	) != nil {
		return Result{}, ErrGuestStaging
	}
	self, err := input.readStableFile(
		commandName(value.role, value.phase),
		inputExecutableMode,
		maximumExecutableSize,
		value.hooks.afterRead,
	)
	if err != nil {
		return Result{}, err
	}
	if validateThinArm64(self.bytes) != nil ||
		self.revalidate() != nil {
		self.clear()
		return Result{}, ErrGuestStaging
	}
	value.commandSHA256 = self.identity.SHA256
	self.clear()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	liveIdentity, err := value.identity(ctx)
	if err != nil || !liveIdentity.equalFull(value.facts.Identity) {
		return Result{}, ErrGuestStaging
	}
	value.currentIdentity = liveIdentity
	transaction, recovered, err := beginPhaseTransaction(
		value.layout,
		value.role,
		value.phase,
		value.facts.RuntimeTarget,
		value.commandSHA256,
		liveIdentity,
		value.rootUID,
		value.rootGID,
		value.hooks.afterMutation,
	)
	if err != nil {
		return Result{}, err
	}
	value.transaction = transaction
	if recovered != nil {
		return *recovered, nil
	}
	defer transaction.abortUncommitted()

	switch value.phase {
	case LayerAStage:
		return value.runLayerA(input)
	case LayerASSHBootstrap:
		return value.runLayerASSHBootstrap(input)
	case LayerBPrepare:
		return value.runLayerBPrepare(input)
	case LayerBPin:
		return value.runLayerBPin(input)
	default:
		return Result{}, ErrGuestStaging
	}
}

func (value *runner) runLayerA(
	input *stableDirectory,
) (Result, error) {
	reviewPath := value.layout.review(value.role)
	if !pathAbsent(reviewPath) {
		return Result{}, ErrGuestStaging
	}
	if value.role == ClientRole {
		for _, path := range []string{
			value.layout.ClientStageRoot,
			filepath.Join(value.layout.Applications, AppInputName),
		} {
			if !pathAbsent(path) {
				return Result{}, ErrGuestStaging
			}
		}
	} else {
		for _, path := range []string{
			value.layout.PeerSupervisor,
			value.layout.PeerChild,
			value.layout.ListenerAuditor,
			value.layout.ForcedCommand,
		} {
			if !pathAbsent(path) {
				return Result{}, ErrGuestStaging
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	inventory, err := value.collect(ctx)
	if err != nil {
		return Result{}, ErrGuestStaging
	}
	encodedInventory, err := externalpeer.EncodeListenerInventory(inventory)
	if err != nil {
		return Result{}, ErrGuestStaging
	}
	defer clear(encodedInventory)
	// Decode again before any installation so the durable review artifact can
	// never contain a wider shape than the later baseline builder accepts.
	if _, err := externalpeer.DecodeListenerInventory(encodedInventory); err != nil {
		return Result{}, ErrGuestStaging
	}
	appTreeSHA256 := ""
	appManifestSHA256 := ""
	if value.role == ClientRole {
		appTreeSHA256, appManifestSHA256, err =
			value.stageClientLayerA(input)
		if err != nil {
			return Result{}, err
		}
	} else if err := value.stagePeerLayerA(input); err != nil {
		return Result{}, err
	}
	witnessBytes, err := encodeVMIdentityWitness(vmIdentityWitness{
		SchemaVersion:     1,
		Role:              value.role,
		RuntimeTarget:     value.facts.RuntimeTarget,
		CollectedAt:       time.Now().UTC().Unix(),
		Identity:          value.currentIdentity,
		AppTreeSHA256:     appTreeSHA256,
		AppManifestSHA256: appManifestSHA256,
	})
	if err != nil {
		return Result{}, err
	}
	defer clear(witnessBytes)
	if _, err := value.transaction.stageDirectory(
		reviewPath,
		reviewDirectoryMode,
		mustDirectoryMode(filepath.Dir(reviewPath)),
		func(pendingReview string) error {
			if _, err := createRootFile(
				filepath.Join(pendingReview, ListenerInventoryName),
				encodedInventory,
				value.rootUID,
				value.rootGID,
				reviewFileMode,
			); err != nil {
				return err
			}
			_, err := createRootFile(
				filepath.Join(pendingReview, VMIdentityWitnessName),
				witnessBytes,
				value.rootUID,
				value.rootGID,
				reviewFileMode,
			)
			return err
		},
	); err != nil {
		return Result{}, err
	}
	finalIdentity, err := value.collectAndRequireIdentity(
		value.currentIdentity, true,
	)
	if err != nil {
		return Result{}, err
	}
	result := Result{
		Role: value.role, Phase: value.phase,
		ReviewPath: filepath.Join(reviewPath, ListenerInventoryName),
		ReviewSHA:  hashHex(encodedInventory),
	}
	return value.transaction.commit(result, finalIdentity)
}

func (value *runner) stageClientLayerA(
	input *stableDirectory,
) (string, string, error) {
	manifestBlob, err := input.readStableFile(
		AppTreeManifestInputName,
		inputFileMode,
		maximumAppManifestSize,
		value.hooks.afterRead,
	)
	if err != nil {
		return "", "", err
	}
	defer manifestBlob.clear()
	manifest, err := decodeAppTreeManifest(manifestBlob.bytes)
	if err != nil || manifestBlob.revalidate() != nil {
		return "", "", ErrGuestStaging
	}
	config, err := input.readStableFile(
		MihomoConfigInputName, inputFileMode,
		externalpeer.MaxDescriptorSize, value.hooks.afterRead,
	)
	if err != nil {
		return "", "", err
	}
	defer config.clear()
	if config.identity.SHA256 != vmexternalpeerlab.MihomoConfigSHA256 ||
		config.revalidate() != nil {
		return "", "", ErrGuestStaging
	}
	if _, err := value.transaction.stageDirectory(
		value.layout.ClientStageRoot,
		0o700,
		mustDirectoryMode(filepath.Dir(value.layout.ClientStageRoot)),
		func(pendingStage string) error {
			for _, executable := range []struct {
				input string
				name  string
				mode  os.FileMode
			}{
				{
					"kyclash-vm-external-peer-lab-supervisor",
					"kyclash-vm-external-peer-lab-supervisor",
					rootExecutableMode,
				},
				{
					"kyclash-vm-external-peer-lab-harness",
					"kyclash-vm-external-peer-lab-harness",
					rootPrivateExecMode,
				},
				{MihomoInputName, MihomoInputName, rootPrivateExecMode},
			} {
				if err := value.copyInputExecutable(
					input,
					executable.input,
					filepath.Join(pendingStage, executable.name),
					executable.mode,
				); err != nil {
					return err
				}
			}
			_, err := createRootFile(
				filepath.Join(pendingStage, MihomoConfigInputName),
				config.bytes,
				value.rootUID,
				value.rootGID,
				rootPrivateMode,
			)
			if err != nil {
				return err
			}
			_, err = createRootFile(
				filepath.Join(
					pendingStage,
					AppTreeManifestInputName,
				),
				manifestBlob.bytes,
				value.rootUID,
				value.rootGID,
				rootPublicKeyMode,
			)
			return err
		},
	); err != nil {
		return "", "", err
	}
	appOutput, err := value.transaction.stageDirectory(
		filepath.Join(value.layout.Applications, AppInputName),
		0o755,
		mustDirectoryMode(value.layout.Applications),
		func(pendingApp string) error {
			return populateAppBundle(
				input,
				pendingApp,
				value.rootUID,
				value.rootGID,
				manifest,
			)
		},
	)
	if err != nil {
		return "", "", err
	}
	if manifestBlob.revalidate() != nil {
		return "", "", ErrGuestStaging
	}
	_ = appOutput
	return manifest.TreeSHA256, manifestBlob.identity.SHA256, nil
}

func (value *runner) stagePeerLayerA(
	input *stableDirectory,
) error {
	for _, artifact := range []struct {
		input  string
		target string
	}{
		{
			"kyclash-vm-external-peer-lab-peer-root-supervisor",
			value.layout.PeerSupervisor,
		},
		{
			"kyclash-vm-external-peer-lab-peer",
			value.layout.PeerChild,
		},
		{
			"kyclash-vm-external-peer-lab-listener-auditor",
			value.layout.ListenerAuditor,
		},
		{
			"kyclash-vm-external-peer-lab-forced-command",
			value.layout.ForcedCommand,
		},
	} {
		if _, err := value.stageInputExecutable(
			input,
			artifact.input,
			artifact.target,
			rootExecutableMode,
			0o755,
		); err != nil {
			return err
		}
	}
	return nil
}

func (value *runner) installInputExecutable(
	input *stableDirectory,
	inputName string,
	target string,
	targetMode os.FileMode,
) error {
	blob, err := input.readStableFile(
		inputName, inputExecutableMode,
		maximumExecutableSize, value.hooks.afterRead,
	)
	if err != nil {
		return err
	}
	defer blob.clear()
	if validateThinArm64(blob.bytes) != nil ||
		blob.revalidate() != nil {
		return ErrGuestStaging
	}
	_, err = createRootFile(
		target, blob.bytes,
		value.rootUID, value.rootGID, targetMode,
	)
	return err
}

func (value *runner) copyInputExecutable(
	input *stableDirectory,
	inputName string,
	target string,
	targetMode os.FileMode,
) error {
	blob, err := input.readStableFile(
		inputName,
		inputExecutableMode,
		maximumExecutableSize,
		value.hooks.afterRead,
	)
	if err != nil {
		return err
	}
	defer blob.clear()
	if validateThinArm64(blob.bytes) != nil || blob.revalidate() != nil {
		return ErrGuestStaging
	}
	_, err = createRootFile(
		target,
		blob.bytes,
		value.rootUID,
		value.rootGID,
		targetMode,
	)
	return err
}

func (value *runner) stageInputExecutable(
	input *stableDirectory,
	inputName string,
	target string,
	targetMode os.FileMode,
	parentMode os.FileMode,
) (fileIdentity, error) {
	blob, err := input.readStableFile(
		inputName,
		inputExecutableMode,
		maximumExecutableSize,
		value.hooks.afterRead,
	)
	if err != nil {
		return fileIdentity{}, err
	}
	defer blob.clear()
	if validateThinArm64(blob.bytes) != nil || blob.revalidate() != nil {
		return fileIdentity{}, ErrGuestStaging
	}
	return value.transaction.stageFile(
		target, blob.bytes, targetMode, parentMode,
	)
}

func (value *runner) runLayerBPrepare(
	input *stableDirectory,
) (Result, error) {
	reviewPath := value.layout.review(value.role)
	if err := requireReviewNames(
		reviewPath, value.rootUID, value.rootGID,
		sshBootstrapReviewNames(),
	); err != nil {
		return Result{}, err
	}
	inputs, err := value.readLayerBInputs(input)
	if err != nil {
		return Result{}, err
	}
	defer inputs.clear()
	inventoryBlob, err := readStableRootFile(
		filepath.Join(reviewPath, ListenerInventoryName),
		value.rootUID, value.rootGID, reviewFileMode,
		externalpeer.MaxChildControlFrame,
	)
	if err != nil {
		return Result{}, err
	}
	defer inventoryBlob.directory.close()
	defer inventoryBlob.clear()
	inventory, err := externalpeer.DecodeListenerInventory(
		inventoryBlob.bytes,
	)
	if err != nil {
		return Result{}, ErrGuestStaging
	}
	baseline, err := externalpeer.NewListenerBaseline(
		roleVM(value.role, inputs.config), inventory,
	)
	if err != nil {
		return Result{}, ErrGuestStaging
	}
	encodedBaseline, err := externalpeer.EncodeListenerBaseline(baseline)
	if err != nil {
		return Result{}, ErrGuestStaging
	}
	defer clear(encodedBaseline)
	witness := reviewWitness{
		SchemaVersion:     1,
		Role:              value.role,
		ConfigSHA256:      inputs.configBytes.identity.SHA256,
		ExpectationSHA256: inputs.expectationBytes.identity.SHA256,
		CourierKeySHA256:  inputs.courierPublicKey.identity.SHA256,
		InventorySHA256:   inventoryBlob.identity.SHA256,
		BaselineSHA256:    hashHex(encodedBaseline),
	}
	witnessBytes, err := encodeReviewWitness(witness)
	if err != nil {
		return Result{}, err
	}
	defer clear(witnessBytes)
	if value.hooks.beforeCommit != nil {
		value.hooks.beforeCommit()
	}
	if inputs.revalidate() != nil ||
		inventoryBlob.revalidate() != nil {
		return Result{}, ErrGuestStaging
	}
	baselinePath := filepath.Join(reviewPath, BaselineCandidateName)
	if _, err := value.transaction.stageFile(
		baselinePath, encodedBaseline,
		reviewFileMode, reviewDirectoryMode,
	); err != nil {
		return Result{}, err
	}
	if _, err := value.transaction.stageFile(
		filepath.Join(reviewPath, ReviewWitnessName),
		witnessBytes,
		reviewFileMode,
		reviewDirectoryMode,
	); err != nil {
		return Result{}, err
	}
	finalIdentity, err := value.collectAndRequireIdentity(
		value.currentIdentity, true,
	)
	if err != nil {
		return Result{}, err
	}
	value.currentIdentity = finalIdentity
	if value.validateCurrentIdentityForLayerB(inputs.config) != nil {
		return Result{}, ErrGuestStaging
	}
	result := Result{
		Role: value.role, Phase: value.phase,
		ReviewPath: baselinePath, ReviewSHA: witness.BaselineSHA256,
	}
	return value.transaction.commit(result, finalIdentity)
}

func (value *runner) runLayerBPin(
	input *stableDirectory,
) (Result, error) {
	reviewPath := value.layout.review(value.role)
	if err := requireReviewNames(
		reviewPath, value.rootUID, value.rootGID,
		append(sshBootstrapReviewNames(), []string{
			BaselineCandidateName,
			ReviewWitnessName,
		}...),
	); err != nil {
		return Result{}, err
	}
	inputs, err := value.readLayerBInputs(input)
	if err != nil {
		return Result{}, err
	}
	defer inputs.clear()
	approved, err := input.readStableFile(
		ApprovedListenerBaselineName,
		inputFileMode,
		externalpeer.MaxChildControlFrame,
		value.hooks.afterRead,
	)
	if err != nil {
		return Result{}, err
	}
	defer approved.clear()
	candidate, err := readStableRootFile(
		filepath.Join(reviewPath, BaselineCandidateName),
		value.rootUID, value.rootGID, reviewFileMode,
		externalpeer.MaxChildControlFrame,
	)
	if err != nil {
		return Result{}, err
	}
	defer candidate.directory.close()
	defer candidate.clear()
	witnessBlob, err := readStableRootFile(
		filepath.Join(reviewPath, ReviewWitnessName),
		value.rootUID, value.rootGID, reviewFileMode,
		externalpeer.MaxDescriptorSize,
	)
	if err != nil {
		return Result{}, err
	}
	defer witnessBlob.directory.close()
	defer witnessBlob.clear()
	witness, err := decodeReviewWitness(witnessBlob.bytes)
	if err != nil || witness.Role != value.role ||
		witness.ConfigSHA256 != inputs.configBytes.identity.SHA256 ||
		witness.ExpectationSHA256 != inputs.expectationBytes.identity.SHA256 ||
		witness.CourierKeySHA256 != inputs.courierPublicKey.identity.SHA256 ||
		witness.BaselineSHA256 != candidate.identity.SHA256 ||
		!bytes.Equal(approved.bytes, candidate.bytes) {
		return Result{}, ErrGuestStaging
	}
	baseline, err := externalpeer.DecodeListenerBaseline(approved.bytes)
	if err != nil ||
		baseline.ValidateForVM(roleVM(value.role, inputs.config)) != nil {
		return Result{}, ErrGuestStaging
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	currentInventory, err := value.collect(ctx)
	if err != nil ||
		externalpeer.ValidateBaselineListenerInventory(
			currentInventory, baseline,
		) != nil {
		return Result{}, ErrGuestStaging
	}
	if err := value.verifyLocalTicketArtifacts(inputs); err != nil {
		return Result{}, err
	}
	if value.hooks.beforeCommit != nil {
		value.hooks.beforeCommit()
	}
	if inputs.revalidate() != nil ||
		approved.revalidate() != nil ||
		candidate.revalidate() != nil ||
		witnessBlob.revalidate() != nil {
		return Result{}, ErrGuestStaging
	}
	if err := value.preflightPinDestinations(); err != nil {
		return Result{}, err
	}
	configIdentity, expectationIdentity, baselineIdentity, err :=
		value.pinSharedConfiguration(inputs, approved.bytes)
	if err != nil {
		return Result{}, err
	}
	if value.role == ClientRole {
		err = value.pinClientManifest(
			inputs,
			configIdentity,
			expectationIdentity,
			baselineIdentity,
		)
	} else {
		err = value.pinPeerManifest(
			inputs,
			configIdentity,
			expectationIdentity,
			baselineIdentity,
		)
	}
	if err != nil {
		return Result{}, err
	}
	finalIdentity, err := value.collectAndRequireIdentity(
		value.currentIdentity, true,
	)
	if err != nil {
		return Result{}, err
	}
	value.currentIdentity = finalIdentity
	if value.validateCurrentIdentityForLayerB(inputs.config) != nil {
		return Result{}, ErrGuestStaging
	}
	result := Result{
		Role: value.role, Phase: value.phase,
		ReviewPath: filepath.Join(reviewPath, candidate.name),
		ReviewSHA:  candidate.identity.SHA256,
	}
	return value.transaction.commit(result, finalIdentity)
}

func (value *runner) preflightPinDestinations() error {
	baselineName := filepath.Base(externalpeer.PeerListenerBaselinePath)
	if value.role == ClientRole {
		baselineName = filepath.Base(externalpeer.ClientListenerBaselinePath)
	}
	paths := []string{
		filepath.Join(value.layout.Configuration, PeerConfigInputName),
		filepath.Join(
			value.layout.Configuration,
			TicketExpectationInputName,
		),
		filepath.Join(value.layout.Configuration, baselineName),
	}
	if value.role == ClientRole {
		paths = append(
			paths,
			filepath.Join(
				value.layout.ClientStageRoot,
				CourierPublicKeyInputName,
			),
			filepath.Join(
				value.layout.ClientStageRoot,
				filepath.Base(vmexternalpeerlab.AppManifestPath),
			),
		)
	} else {
		paths = append(
			paths,
			filepath.Join(
				value.layout.Configuration,
				filepath.Base(externalpeer.PeerStagingManifestPath),
			),
		)
	}
	for _, path := range paths {
		if !pathAbsent(path) {
			return ErrGuestStaging
		}
	}
	return nil
}

func (value *runner) readLayerBInputs(
	input *stableDirectory,
) (layerBInputs, error) {
	configBlob, err := input.readStableFile(
		PeerConfigInputName, inputFileMode,
		externalpeer.MaxDescriptorSize, value.hooks.afterRead,
	)
	if err != nil {
		return layerBInputs{}, err
	}
	expectationBlob, err := input.readStableFile(
		TicketExpectationInputName, inputFileMode,
		externalpeer.MaxDescriptorSize, value.hooks.afterRead,
	)
	if err != nil {
		configBlob.clear()
		return layerBInputs{}, err
	}
	keyBlob, err := input.readStableFile(
		CourierPublicKeyInputName, inputFileMode,
		ed25519.PublicKeySize, value.hooks.afterRead,
	)
	if err != nil {
		configBlob.clear()
		expectationBlob.clear()
		return layerBInputs{}, err
	}
	result := layerBInputs{
		configBytes:      configBlob,
		expectationBytes: expectationBlob,
		courierPublicKey: keyBlob,
	}
	config, err := externalpeer.DecodePeerSupervisorConfig(configBlob.bytes)
	if err != nil ||
		config.ConsoleUID != value.facts.ConsoleUID ||
		config.ConsoleGID != value.facts.ConsoleGID ||
		config.PeerChildUID != restrictedSSHUID ||
		config.PeerChildGID != restrictedSSHGID ||
		roleVM(value.role, config).VMName != map[Role]string{
			ClientRole: externalpeer.ClientVMName,
			PeerRole:   externalpeer.PeerVMName,
		}[value.role] {
		result.clear()
		return layerBInputs{}, ErrGuestStaging
	}
	if value.validateCurrentIdentityForLayerB(config) != nil {
		result.clear()
		return layerBInputs{}, ErrGuestStaging
	}
	expectation, err := externalpeer.DecodeRunTicketExpectation(
		expectationBlob.bytes,
	)
	if err != nil || len(keyBlob.bytes) != ed25519.PublicKeySize {
		result.clear()
		return layerBInputs{}, ErrGuestStaging
	}
	result.config = config
	result.expectation = expectation
	return result, nil
}

func (inputs *layerBInputs) clear() {
	if inputs == nil {
		return
	}
	inputs.configBytes.clear()
	inputs.expectationBytes.clear()
	inputs.courierPublicKey.clear()
}

func (inputs layerBInputs) revalidate() error {
	if inputs.configBytes.revalidate() != nil ||
		inputs.expectationBytes.revalidate() != nil ||
		inputs.courierPublicKey.revalidate() != nil {
		return ErrGuestStaging
	}
	return nil
}

func (value *runner) collectAndRequireIdentity(
	expected VMIdentity,
	full bool,
) (VMIdentity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	current, err := value.identity(ctx)
	if err != nil ||
		full && !current.equalFull(expected) ||
		!full && !current.equalImmutable(expected) {
		return VMIdentity{}, ErrGuestStaging
	}
	return current, nil
}

func (value *runner) readLayerAIdentityWitness() (vmIdentityWitness, error) {
	path := filepath.Join(
		value.layout.review(value.role), VMIdentityWitnessName,
	)
	blob, err := readStableRootFile(
		path,
		value.rootUID,
		value.rootGID,
		reviewFileMode,
		externalpeer.MaxDescriptorSize,
	)
	if err != nil {
		return vmIdentityWitness{}, err
	}
	defer blob.directory.close()
	defer blob.clear()
	witness, err := decodeVMIdentityWitness(blob.bytes)
	if err != nil ||
		witness.Role != value.role ||
		witness.RuntimeTarget != value.facts.RuntimeTarget ||
		blob.revalidate() != nil {
		return vmIdentityWitness{}, ErrGuestStaging
	}
	return witness, nil
}

func (value *runner) validateCurrentIdentityForLayerB(
	config externalpeer.PeerSupervisorConfig,
) error {
	witness, err := value.readLayerAIdentityWitness()
	if err != nil ||
		!value.currentIdentity.equalImmutable(witness.Identity) {
		return ErrGuestStaging
	}
	roleConfig := roleVM(value.role, config)
	if !strings.EqualFold(
		value.currentIdentity.PlatformUUID, roleConfig.PlatformUUID,
	) ||
		!strings.EqualFold(value.currentIdentity.En0MAC, roleConfig.MAC) ||
		value.currentIdentity.En0IPv4 != roleConfig.IPv4 ||
		value.currentIdentity.SSHHostKeyFingerprint !=
			roleConfig.SSHHostFingerprint {
		return ErrGuestStaging
	}
	hostKeyBlob, err := readStableRootFile(
		filepath.Join(
			value.layout.review(value.role), SSHHostPublicKeyName,
		),
		value.rootUID,
		value.rootGID,
		reviewFileMode,
		maximumSSHPublicKey,
	)
	if err != nil {
		return err
	}
	defer hostKeyBlob.directory.close()
	defer hostKeyBlob.clear()
	hostKey, err := parseCanonicalRawED25519(hostKeyBlob.bytes)
	if err != nil ||
		hostKeyBlob.identity.SHA256 !=
			value.currentIdentity.SSHHostPublicKeySHA256 ||
		ssh.FingerprintSHA256(hostKey) !=
			value.currentIdentity.SSHHostKeyFingerprint ||
		hostKeyBlob.revalidate() != nil {
		return ErrGuestStaging
	}
	fingerprintBlob, err := readStableRootFile(
		filepath.Join(
			value.layout.review(value.role), SSHHostFingerprintName,
		),
		value.rootUID,
		value.rootGID,
		reviewFileMode,
		maximumSSHPublicKey,
	)
	if err != nil {
		return err
	}
	defer fingerprintBlob.directory.close()
	defer fingerprintBlob.clear()
	if string(fingerprintBlob.bytes) !=
		value.currentIdentity.SSHHostKeyFingerprint+"\n" ||
		fingerprintBlob.revalidate() != nil {
		return ErrGuestStaging
	}
	if value.role == ClientRole {
		manifestBlob, err := readStableRootFile(
			filepath.Join(
				value.layout.ClientStageRoot,
				AppTreeManifestInputName,
			),
			value.rootUID,
			value.rootGID,
			rootPublicKeyMode,
			maximumAppManifestSize,
		)
		if err != nil {
			return err
		}
		defer manifestBlob.directory.close()
		defer manifestBlob.clear()
		manifest, err := decodeAppTreeManifest(manifestBlob.bytes)
		if err != nil ||
			manifest.TreeSHA256 != witness.AppTreeSHA256 ||
			manifestBlob.identity.SHA256 != witness.AppManifestSHA256 ||
			manifestBlob.revalidate() != nil {
			return ErrGuestStaging
		}
		appRoot, err := openStableDirectory(
			filepath.Join(value.layout.Applications, AppInputName),
			value.rootUID,
			value.rootGID,
			0o755,
		)
		if err != nil {
			return err
		}
		defer appRoot.close()
		if verifyStableAppTree(appRoot, manifest, 0o755) != nil {
			return ErrGuestStaging
		}
	}
	return nil
}

func roleVM(
	role Role,
	config externalpeer.PeerSupervisorConfig,
) externalpeer.SupervisorVMConfig {
	if role == ClientRole {
		return config.Client
	}
	return config.Peer
}

func requireReviewNames(
	path string,
	uid uint32,
	gid uint32,
	names []string,
) error {
	directory, err := openStableDirectory(
		path, uid, gid, reviewDirectoryMode,
	)
	if err != nil {
		return err
	}
	defer directory.close()
	return directory.requireExactNames(names)
}

func hashHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func encodeReviewWitness(value reviewWitness) ([]byte, error) {
	if value.Validate() != nil {
		return nil, ErrGuestStaging
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > externalpeer.MaxDescriptorSize {
		return nil, ErrGuestStaging
	}
	return append(encoded, '\n'), nil
}

func decodeReviewWitness(data []byte) (reviewWitness, error) {
	if len(data) == 0 || len(data) > externalpeer.MaxDescriptorSize {
		return reviewWitness{}, ErrGuestStaging
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value reviewWitness
	if decoder.Decode(&value) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		value.Validate() != nil {
		return reviewWitness{}, ErrGuestStaging
	}
	return value, nil
}

func (value reviewWitness) Validate() error {
	if value.SchemaVersion != 1 ||
		(value.Role != ClientRole && value.Role != PeerRole) {
		return ErrGuestStaging
	}
	for _, digest := range []string{
		value.ConfigSHA256,
		value.ExpectationSHA256,
		value.CourierKeySHA256,
		value.InventorySHA256,
		value.BaselineSHA256,
	} {
		if len(digest) != 64 {
			return ErrGuestStaging
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return ErrGuestStaging
		}
	}
	return nil
}

func (value *runner) verifyLocalTicketArtifacts(
	inputs layerBInputs,
) error {
	expected := map[string]struct {
		path string
		mode os.FileMode
	}{
		"peer-config": {
			path: "",
			mode: inputFileMode,
		},
	}
	if value.role == ClientRole {
		expected["app"] = struct {
			path string
			mode os.FileMode
		}{
			filepath.Join(
				value.layout.Applications,
				AppInputName,
				"Contents",
				"MacOS",
				"clash-verge",
			),
			rootExecutableMode,
		}
		expected["client-supervisor"] = struct {
			path string
			mode os.FileMode
		}{
			filepath.Join(
				value.layout.ClientStageRoot,
				"kyclash-vm-external-peer-lab-supervisor",
			),
			rootExecutableMode,
		}
		expected["client-harness"] = struct {
			path string
			mode os.FileMode
		}{
			filepath.Join(
				value.layout.ClientStageRoot,
				"kyclash-vm-external-peer-lab-harness",
			),
			rootPrivateExecMode,
		}
	} else {
		expected["peer-supervisor"] = struct {
			path string
			mode os.FileMode
		}{value.layout.PeerSupervisor, rootExecutableMode}
		expected["peer-child"] = struct {
			path string
			mode os.FileMode
		}{value.layout.PeerChild, rootExecutableMode}
		expected["listener-auditor"] = struct {
			path string
			mode os.FileMode
		}{value.layout.ListenerAuditor, rootExecutableMode}
		expected["forced-command-helper"] = struct {
			path string
			mode os.FileMode
		}{value.layout.ForcedCommand, rootExecutableMode}
	}
	for _, artifact := range inputs.expectation.Files {
		expectedArtifact, applies := expected[artifact.Name]
		if !applies {
			continue
		}
		var size uint64
		var digest string
		if artifact.Name == "peer-config" {
			size = uint64(len(inputs.configBytes.bytes))
			digest = inputs.configBytes.identity.SHA256
		} else {
			blob, err := readStableRootFile(
				expectedArtifact.path,
				value.rootUID, value.rootGID,
				expectedArtifact.mode,
				maximumExecutableSize,
			)
			if err != nil {
				return err
			}
			if validateThinArm64(blob.bytes) != nil {
				blob.clear()
				_ = blob.directory.close()
				return ErrGuestStaging
			}
			size = uint64(len(blob.bytes))
			digest = blob.identity.SHA256
			blob.clear()
			if blob.directory.close() != nil {
				return ErrGuestStaging
			}
		}
		if artifact.Length != size || artifact.SHA256 != digest {
			return ErrGuestStaging
		}
		delete(expected, artifact.Name)
	}
	if len(expected) != 0 {
		return ErrGuestStaging
	}
	return nil
}

func (value *runner) pinSharedConfiguration(
	inputs layerBInputs,
	baseline []byte,
) (fileIdentity, fileIdentity, fileIdentity, error) {
	configPath := filepath.Join(
		value.layout.Configuration, PeerConfigInputName,
	)
	expectationPath := filepath.Join(
		value.layout.Configuration, TicketExpectationInputName,
	)
	baselineName := externalpeer.PeerListenerBaselinePath
	if value.role == ClientRole {
		baselineName = externalpeer.ClientListenerBaselinePath
	}
	baselinePath := filepath.Join(
		value.layout.Configuration, filepath.Base(baselineName),
	)
	for _, path := range []string{
		configPath, expectationPath, baselinePath,
	} {
		if !pathAbsent(path) {
			return fileIdentity{}, fileIdentity{}, fileIdentity{},
				ErrGuestStaging
		}
	}
	configIdentity, err := value.transaction.stageFile(
		configPath, inputs.configBytes.bytes,
		rootPrivateMode, 0o700,
	)
	if err != nil {
		return fileIdentity{}, fileIdentity{}, fileIdentity{}, err
	}
	expectationIdentity, err := value.transaction.stageFile(
		expectationPath, inputs.expectationBytes.bytes,
		rootPrivateMode, 0o700,
	)
	if err != nil {
		return fileIdentity{}, fileIdentity{}, fileIdentity{}, err
	}
	baselineIdentity, err := value.transaction.stageFile(
		baselinePath, baseline,
		rootPrivateMode, 0o700,
	)
	if err != nil {
		return fileIdentity{}, fileIdentity{}, fileIdentity{}, err
	}
	return configIdentity, expectationIdentity, baselineIdentity, nil
}

func (value *runner) pinClientManifest(
	inputs layerBInputs,
	config fileIdentity,
	expectation fileIdentity,
	baseline fileIdentity,
) error {
	keyPath := filepath.Join(
		value.layout.ClientStageRoot,
		CourierPublicKeyInputName,
	)
	manifestPath := filepath.Join(
		value.layout.ClientStageRoot,
		filepath.Base(vmexternalpeerlab.AppManifestPath),
	)
	if !pathAbsent(keyPath) || !pathAbsent(manifestPath) {
		return ErrGuestStaging
	}
	key, err := value.transaction.stageFile(
		keyPath, inputs.courierPublicKey.bytes,
		rootPublicKeyMode, 0o700,
	)
	if err != nil {
		return err
	}
	app, err := rootExecutableIdentity(
		filepath.Join(
			value.layout.Applications,
			AppInputName,
			"Contents",
			"MacOS",
			"clash-verge",
		),
		value.rootUID, value.rootGID, rootExecutableMode,
	)
	if err != nil {
		return err
	}
	harness, err := rootExecutableIdentity(
		filepath.Join(
			value.layout.ClientStageRoot,
			"kyclash-vm-external-peer-lab-harness",
		),
		value.rootUID, value.rootGID, rootPrivateExecMode,
	)
	if err != nil {
		return err
	}
	treeWitness, err := value.readLayerAIdentityWitness()
	if err != nil ||
		!validSHA256(treeWitness.AppTreeSHA256) ||
		!validSHA256(treeWitness.AppManifestSHA256) {
		return ErrGuestStaging
	}
	treeManifest, err := readStableRootFile(
		filepath.Join(
			value.layout.ClientStageRoot,
			AppTreeManifestInputName,
		),
		value.rootUID,
		value.rootGID,
		rootPublicKeyMode,
		maximumAppManifestSize,
	)
	if err != nil {
		return err
	}
	defer treeManifest.directory.close()
	defer treeManifest.clear()
	decodedTree, err := decodeAppTreeManifest(treeManifest.bytes)
	if err != nil ||
		decodedTree.TreeSHA256 != treeWitness.AppTreeSHA256 ||
		treeManifest.identity.SHA256 != treeWitness.AppManifestSHA256 ||
		treeManifest.revalidate() != nil {
		return ErrGuestStaging
	}
	manifest := vmexternalpeerlab.AppManifestV2{
		SchemaVersion:                vmexternalpeerlab.AppManifestSchemaVersion,
		RuntimeTarget:                vmexternalpeerlab.RuntimeTarget,
		ExecutablePath:               vmexternalpeerlab.AppExecutablePath,
		ExpectedAuditUID:             value.facts.ConsoleUID,
		ExecutableUID:                0,
		ExecutableMode:               rootExecutableMode,
		ExecutableDevice:             app.Device,
		ExecutableInode:              app.Inode,
		ExecutableSize:               app.Size,
		ExecutableSHA256:             app.SHA256,
		AppTreeSHA256:                treeWitness.AppTreeSHA256,
		AppTreeManifestSHA256:        treeWitness.AppManifestSHA256,
		Architecture:                 "arm64",
		RunTicketExpectationSHA256:   expectation.SHA256,
		PeerConfigSHA256:             config.SHA256,
		CourierPublicKeySHA256:       key.SHA256,
		ClientListenerBaselineSHA256: baseline.SHA256,
		HarnessExecutableDevice:      harness.Device,
		HarnessExecutableInode:       harness.Inode,
		HarnessExecutableSize:        harness.Size,
		HarnessExecutableSHA256:      harness.SHA256,
	}
	encoded, err := vmexternalpeerlab.EncodeAppManifestV2(manifest)
	if err != nil {
		return ErrGuestStaging
	}
	defer clear(encoded)
	_, err = value.transaction.stageFile(
		manifestPath, encoded,
		rootPublicKeyMode, 0o700,
	)
	return err
}

func (value *runner) pinPeerManifest(
	inputs layerBInputs,
	config fileIdentity,
	expectation fileIdentity,
	baseline fileIdentity,
) error {
	manifestPath := filepath.Join(
		value.layout.Configuration,
		filepath.Base(externalpeer.PeerStagingManifestPath),
	)
	if !pathAbsent(manifestPath) {
		return ErrGuestStaging
	}
	supervisor, err := rootExecutableIdentity(
		value.layout.PeerSupervisor,
		value.rootUID, value.rootGID, rootExecutableMode,
	)
	if err != nil {
		return err
	}
	child, err := rootExecutableIdentity(
		value.layout.PeerChild,
		value.rootUID, value.rootGID, rootExecutableMode,
	)
	if err != nil {
		return err
	}
	auditor, err := rootExecutableIdentity(
		value.layout.ListenerAuditor,
		value.rootUID, value.rootGID, rootExecutableMode,
	)
	if err != nil {
		return err
	}
	helper, err := rootExecutableIdentity(
		value.layout.ForcedCommand,
		value.rootUID, value.rootGID, rootExecutableMode,
	)
	if err != nil {
		return err
	}
	staged := func(
		path string,
		mode uint32,
		identity fileIdentity,
	) externalpeer.StagedFile {
		return externalpeer.StagedFile{
			Path: path, SHA256: identity.SHA256,
			UID: 0, Mode: mode,
			Device: identity.Device, Inode: identity.Inode,
			Size: identity.Size,
		}
	}
	manifest := externalpeer.PeerStagingManifest{
		SchemaVersion: externalpeer.SchemaVersion,
		PeerSupervisor: staged(
			externalpeer.PeerSupervisorPath,
			rootExecutableMode,
			supervisor,
		),
		PeerChild: staged(
			externalpeer.PeerChildPath,
			rootExecutableMode,
			child,
		),
		PeerConfig: staged(
			externalpeer.PeerFixedConfigPath,
			rootPrivateMode,
			config,
		),
		RunTicketExpectation: staged(
			externalpeer.PeerRunTicketExpectationPath,
			rootPrivateMode,
			expectation,
		),
		PeerListenerBaseline: staged(
			externalpeer.PeerListenerBaselinePath,
			rootPrivateMode,
			baseline,
		),
		ListenerAuditor: staged(
			externalpeer.ListenerAuditorPath,
			rootExecutableMode,
			auditor,
		),
		ForcedCommandHelper: staged(
			externalpeer.ForcedCommandHelperPath,
			rootExecutableMode,
			helper,
		),
		CourierPublicKeyBase64: base64.StdEncoding.EncodeToString(
			inputs.courierPublicKey.bytes,
		),
		CourierPublicKeyFingerprint: externalpeer.HashHex(
			inputs.courierPublicKey.bytes,
		),
	}
	encoded, err := externalpeer.EncodePeerStagingManifest(manifest)
	if err != nil {
		return ErrGuestStaging
	}
	defer clear(encoded)
	_, err = value.transaction.stageFile(
		manifestPath, encoded,
		rootPrivateMode, 0o700,
	)
	return err
}

func rootExecutableIdentity(
	path string,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) (fileIdentity, error) {
	blob, err := readStableRootFile(
		path, uid, gid, mode, maximumExecutableSize,
	)
	if err != nil {
		return fileIdentity{}, err
	}
	defer blob.directory.close()
	defer blob.clear()
	if validateThinArm64(blob.bytes) != nil ||
		blob.revalidate() != nil {
		return fileIdentity{}, ErrGuestStaging
	}
	return blob.identity, nil
}

func ensureConfigurationRoot(
	path string,
	uid uint32,
	gid uint32,
) error {
	if pathAbsent(path) {
		directory, err := ensureCreatedRootDirectory(
			path, uid, gid, 0o700,
		)
		if err != nil {
			return err
		}
		return directory.close()
	}
	directory, err := openStableDirectory(path, uid, gid, 0o700)
	if err != nil {
		return err
	}
	defer directory.close()
	entries, err := directory.file.ReadDir(-1)
	if err != nil || len(entries) != 0 {
		return ErrGuestStaging
	}
	return nil
}

func ensurePeerExecutableParents(
	layout Layout,
	uid uint32,
	gid uint32,
) error {
	parents := []string{
		filepath.Dir(layout.PeerSupervisor),
		filepath.Dir(layout.PeerChild),
	}
	seen := make(map[string]struct{})
	for _, parent := range parents {
		if _, exists := seen[parent]; exists {
			continue
		}
		seen[parent] = struct{}{}
		if pathAbsent(parent) {
			directory, err := ensureCreatedRootDirectory(
				parent, uid, gid, 0o755,
			)
			if err != nil {
				return err
			}
			if directory.close() != nil {
				return ErrGuestStaging
			}
			continue
		}
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o755 {
			return ErrGuestStaging
		}
		identity, err := identityFromInfo(info)
		if err != nil || identity.UID != uid || identity.GID != gid {
			return ErrGuestStaging
		}
	}
	return nil
}

func formatResult(result Result) string {
	switch result.Phase {
	case LayerAStage:
		return fmt.Sprintf(
			"external_peer_%s_layer_a_staged=true\n"+
				"external_peer_%s_listener_inventory_review_required=%s\n"+
				"external_peer_%s_listener_inventory_sha256=%s\n",
			result.Role,
			result.Role, result.ReviewPath,
			result.Role, result.ReviewSHA,
		)
	case LayerASSHBootstrap:
		reviewRoot := filepath.Dir(result.ReviewPath)
		return fmt.Sprintf(
			"external_peer_%s_layer_a_ssh_bootstrap=true\n"+
				"external_peer_%s_ssh_bootstrap_review=%s\n"+
				"external_peer_%s_ssh_bootstrap_witness_sha256=%s\n"+
				"external_peer_%s_ssh_host_public_key_review=%s\n"+
				"external_peer_%s_ssh_host_fingerprint_review=%s\n"+
				"external_peer_%s_runtime_pinned=false\n",
			result.Role,
			result.Role, result.ReviewPath,
			result.Role, result.ReviewSHA,
			result.Role, filepath.Join(reviewRoot, SSHHostPublicKeyName),
			result.Role, filepath.Join(reviewRoot, SSHHostFingerprintName),
			result.Role,
		)
	case LayerBPrepare:
		return fmt.Sprintf(
			"external_peer_%s_layer_b_prepared=true\n"+
				"external_peer_%s_listener_baseline_review_required=%s\n"+
				"external_peer_%s_listener_baseline_sha256=%s\n"+
				"external_peer_%s_runtime_pinned=false\n",
			result.Role,
			result.Role, result.ReviewPath,
			result.Role, result.ReviewSHA,
			result.Role,
		)
	case LayerBPin:
		return fmt.Sprintf(
			"external_peer_%s_layer_b_pinned=true\n"+
				"external_peer_%s_approved_listener_baseline_sha256=%s\n",
			result.Role,
			result.Role, result.ReviewSHA,
		)
	default:
		return ""
	}
}

func PrintResult(result Result) {
	_, _ = os.Stdout.WriteString(formatResult(result))
}
