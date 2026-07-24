package externalpeerhost

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/externalpeergueststaging"
)

type LayerBInputState string

const (
	LayerBManagementHostKeyPinRequired     LayerBInputState = "management-host-key-pin-required"
	LayerBPreparePublished                 LayerBInputState = "layer-b-prepare-inputs-published"
	LayerBListenerBaselineApprovalRequired LayerBInputState = "listener-baseline-approval-required"
	LayerBPinPublished                     LayerBInputState = "layer-b-pin-inputs-published"
)

func InitializeLayerBInputs(
	ctx context.Context,
	layout Layout,
	executor CommandExecutor,
	clock RunnerClock,
	tart TartResolver,
) (LayerBInputState, error) {
	if ctx == nil || executor == nil || clock == nil || tart == nil {
		return "", ErrUnsafeHostCourier
	}
	builds, err := loadExternalPeerBuildInputs(layout)
	if err != nil {
		return "", fmt.Errorf("layer-b build inputs: %w", err)
	}
	courierPublic, managementPublic, err := loadPublicInputKeys(layout)
	if err != nil {
		return "", fmt.Errorf("layer-b public keys: %w", err)
	}
	defer clear(courierPublic)
	defer clearByteSlices(managementPublic)
	if err := requirePublishedLayerAInputs(
		layout,
		builds,
		managementPublic,
	); err != nil {
		return "", fmt.Errorf("layer-b prior layer-a inputs: %w", err)
	}
	client, err := openGuestReviewSet(
		layout,
		"client",
		builds,
		managementPublic[0],
	)
	if err != nil {
		return "", fmt.Errorf("layer-b client review: %w", err)
	}
	defer client.close()
	peer, err := openGuestReviewSet(
		layout,
		"peer",
		builds,
		managementPublic[1],
	)
	if err != nil {
		return "", fmt.Errorf("layer-b peer review: %w", err)
	}
	defer peer.close()
	if client.prepared() != peer.prepared() {
		return "", ErrUnsafeHostCourier
	}
	clientIP, err := resolveLayerBAddress(
		ctx,
		layout,
		executor,
		tart,
		"client",
		externalpeer.ClientVMName,
	)
	if err != nil {
		return "", fmt.Errorf("layer-b client arp: %w", err)
	}
	peerIP, err := resolveLayerBAddress(
		ctx,
		layout,
		executor,
		tart,
		"peer",
		externalpeer.PeerVMName,
	)
	if err != nil {
		return "", fmt.Errorf("layer-b peer arp: %w", err)
	}
	config, configBytes, err := buildLayerBConfig(
		client,
		peer,
		clientIP,
		peerIP,
	)
	if err != nil {
		return "", fmt.Errorf("layer-b config: %w", err)
	}
	defer clear(configBytes)
	expectation, expectationBytes, err := buildRunTicketExpectation(
		builds,
		configBytes,
	)
	if err != nil {
		return "", fmt.Errorf("layer-b ticket expectation: %w", err)
	}
	defer clear(expectationBytes)
	if err := ensureLayerBWorkspace(
		layout,
		configBytes,
		expectationBytes,
	); err != nil {
		return "", fmt.Errorf("layer-b workspace: %w", err)
	}
	if err := ensureManagementReview(layout, client, peer); err != nil {
		return "", fmt.Errorf("layer-b management review: %w", err)
	}
	pinned, err := managementHostKeysPinned(layout)
	if err != nil {
		return "", fmt.Errorf("layer-b management pin state: %w", err)
	}
	if !pinned {
		return LayerBManagementHostKeyPinRequired, nil
	}
	management, err := openPinnedManagementStore(layout, config)
	if err != nil {
		return "", fmt.Errorf("layer-b pinned management store: %w", err)
	}
	defer management.close()
	if err := proveCurrentGuestIdentities(
		ctx,
		layout,
		executor,
		clock,
		tart,
		management,
		client,
		peer,
	); err != nil {
		return "", fmt.Errorf("layer-b current identity: %w", err)
	}
	if err := publishLayerBPrepareInputs(
		layout,
		builds,
		configBytes,
		expectationBytes,
		courierPublic,
	); err != nil {
		return "", fmt.Errorf("layer-b prepare publication: %w", err)
	}
	if !client.prepared() {
		return LayerBPreparePublished, nil
	}
	if err := validatePreparedGuestReviews(
		client,
		peer,
		config,
		configBytes,
		expectation,
		expectationBytes,
		courierPublic,
	); err != nil {
		return "", fmt.Errorf("layer-b prepared review: %w", err)
	}
	approved, err := loadApprovedListenerBaselines(
		layout,
		client,
		peer,
		configBytes,
		expectationBytes,
		courierPublic,
	)
	if err != nil {
		return "", fmt.Errorf("layer-b listener approval: %w", err)
	}
	if approved == nil {
		return LayerBListenerBaselineApprovalRequired, nil
	}
	defer approved.close()
	if err := publishLayerBPinInputs(
		layout,
		builds,
		approved.clientPath,
		approved.peerPath,
		configBytes,
		expectationBytes,
		courierPublic,
	); err != nil {
		return "", fmt.Errorf("layer-b pin publication: %w", err)
	}
	return LayerBPinPublished, nil
}

func resolveLayerBAddress(
	ctx context.Context,
	layout Layout,
	executor CommandExecutor,
	tart TartResolver,
	role string,
	vmName string,
) (netip.Addr, error) {
	tartPath, err := tart.Resolve()
	if err != nil {
		return netip.Addr{}, err
	}
	expectedPath, err := fixedTartPath(layout)
	if err != nil || tartPath != expectedPath {
		return netip.Addr{}, ErrUnsafeHostCourier
	}
	result, err := executor.Run(ctx, CommandSpec{
		Purpose:    CommandTartARP,
		Executable: tartPath,
		Arguments:  []string{"ip", vmName, "--resolver=arp"},
		Environment: append(
			[]string(nil),
			fixedCommandEnvironment...,
		),
		WorkingDirectory: "/",
		MaximumOutput:    128,
		Role:             role,
	})
	if err != nil {
		clear(result.Stdout)
		return netip.Addr{}, ErrUnsafeHostCourier
	}
	defer clear(result.Stdout)
	return parseTartARP(result.Stdout)
}

func proveCurrentGuestIdentities(
	ctx context.Context,
	layout Layout,
	executor CommandExecutor,
	clock RunnerClock,
	tart TartResolver,
	management *managementStore,
	client *guestReviewSet,
	peer *guestReviewSet,
) error {
	if management == nil || management.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	runner := &StartLabRunner{
		layout:     layout,
		executor:   executor,
		clock:      clock,
		tart:       tart,
		management: management,
	}
	for _, value := range []struct {
		role   string
		review *guestReviewSet
	}{
		{"client", client},
		{"peer", peer},
	} {
		path, err := guestIdentityWitnessPath(value.role)
		if err != nil {
			return err
		}
		payload, found, err := runner.runRemote(
			ctx,
			value.role,
			path,
			remoteActionRead,
			nil,
		)
		if err != nil || !found {
			clear(payload)
			return ErrUnsafeHostCourier
		}
		expected, err := value.review.blob(
			externalpeergueststaging.VMIdentityWitnessName,
		)
		if err != nil || !bytes.Equal(payload, expected.bytes) {
			clear(payload)
			return ErrUnsafeHostCourier
		}
		clear(payload)
	}
	return management.revalidate()
}

func validatePreparedGuestReviews(
	client *guestReviewSet,
	peer *guestReviewSet,
	config externalpeer.PeerSupervisorConfig,
	configBytes []byte,
	expectation externalpeer.RunTicketExpectation,
	expectationBytes []byte,
	courierPublic []byte,
) error {
	if !client.prepared() || !peer.prepared() ||
		config.Validate() != nil ||
		expectation.Validate() != nil ||
		client.revalidate() != nil ||
		peer.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	configHash := hashBytes(configBytes)
	expectationHash := hashBytes(expectationBytes)
	courierHash := hashBytes(courierPublic)
	for _, value := range []struct {
		review *guestReviewSet
		vm     externalpeer.SupervisorVMConfig
	}{
		{client, config.Client},
		{peer, config.Peer},
	} {
		if value.review.baseline.ValidateForVM(value.vm) != nil {
			return ErrUnsafeHostCourier
		}
		inventory := value.review.values[externalpeergueststaging.ListenerInventoryName]
		baseline := value.review.values[externalpeergueststaging.BaselineCandidateName]
		witness := value.review.review
		if witness.ConfigSHA256 != configHash ||
			witness.ExpectationSHA256 != expectationHash ||
			witness.CourierKeySHA256 != courierHash ||
			witness.InventorySHA256 != hashBytes(inventory.bytes) ||
			witness.BaselineSHA256 != hashBytes(baseline.bytes) ||
			externalpeer.ValidateBaselineListenerInventory(
				value.review.inventory,
				*value.review.baseline,
			) != nil {
			return ErrUnsafeHostCourier
		}
	}
	return nil
}

func publishLayerBPrepareInputs(
	layout Layout,
	builds externalPeerBuildInputs,
	config []byte,
	expectation []byte,
	courierPublic []byte,
) error {
	return publishLayerBInputs(
		layout,
		builds,
		LayerBPrepareInputsName,
		filepath.Base(externalpeergueststaging.ClientLayerBPrepareInput),
		filepath.Base(externalpeergueststaging.PeerLayerBPrepareInput),
		"kyclash-vm-external-peer-lab-client-prepare-layer-b",
		"kyclash-vm-external-peer-lab-peer-prepare-layer-b",
		config,
		expectation,
		courierPublic,
		"",
		"",
	)
}

func publishLayerBPinInputs(
	layout Layout,
	builds externalPeerBuildInputs,
	clientBaseline string,
	peerBaseline string,
	config []byte,
	expectation []byte,
	courierPublic []byte,
) error {
	return publishLayerBInputs(
		layout,
		builds,
		LayerBPinInputsName,
		filepath.Base(externalpeergueststaging.ClientLayerBPinInput),
		filepath.Base(externalpeergueststaging.PeerLayerBPinInput),
		"kyclash-vm-external-peer-lab-client-pin-layer-b",
		"kyclash-vm-external-peer-lab-peer-pin-layer-b",
		config,
		expectation,
		courierPublic,
		clientBaseline,
		peerBaseline,
	)
}

func publishLayerBInputs(
	layout Layout,
	builds externalPeerBuildInputs,
	collectionName string,
	clientPhase string,
	peerPhase string,
	clientCommand string,
	peerCommand string,
	config []byte,
	expectation []byte,
	courierPublic []byte,
	clientBaseline string,
	peerBaseline string,
) error {
	artifact := func(name string) (publicFileSpec, error) {
		record, exists := builds.artifacts[name]
		if !exists {
			return publicFileSpec{}, ErrUnsafeHostCourier
		}
		return publicFileSpec{
			name:       name,
			source:     builds.artifactPaths[name],
			sourceMode: 0o755,
			outputMode: 0o500,
			size:       record.ByteLength,
			sha256:     record.SHA256,
		}, nil
	}
	clientExecutable, err := artifact(clientCommand)
	if err != nil {
		return err
	}
	peerExecutable, err := artifact(peerCommand)
	if err != nil {
		return err
	}
	common := func() []publicFileSpec {
		return []publicFileSpec{
			{
				name:       externalpeergueststaging.PeerConfigInputName,
				source:     filepath.Join(layout.Control, PeerConfigName),
				sourceMode: 0o600, outputMode: 0o600,
				size: uint64(len(config)), sha256: hashBytes(config),
			},
			{
				name:       externalpeergueststaging.TicketExpectationInputName,
				source:     filepath.Join(layout.Control, TicketExpectationName),
				sourceMode: 0o600, outputMode: 0o600,
				size:   uint64(len(expectation)),
				sha256: hashBytes(expectation),
			},
			{
				name:       externalpeergueststaging.CourierPublicKeyInputName,
				source:     filepath.Join(layout.PrivateRoot, PublicKeyName),
				sourceMode: 0o600, outputMode: 0o600,
				size:   uint64(len(courierPublic)),
				sha256: hashBytes(courierPublic),
			},
		}
	}
	clientFiles := append([]publicFileSpec{clientExecutable}, common()...)
	peerFiles := append([]publicFileSpec{peerExecutable}, common()...)
	if clientBaseline != "" || peerBaseline != "" {
		if clientBaseline == "" || peerBaseline == "" {
			return ErrUnsafeHostCourier
		}
		for _, value := range []struct {
			files *[]publicFileSpec
			path  string
		}{
			{&clientFiles, clientBaseline},
			{&peerFiles, peerBaseline},
		} {
			digest, size, err := hashStableFile(
				value.path,
				uint32(os.Getuid()),
				0o600,
				externalpeer.MaxChildControlFrame,
			)
			if err != nil {
				return err
			}
			*value.files = append(*value.files, publicFileSpec{
				name:       externalpeergueststaging.ApprovedListenerBaselineName,
				source:     value.path,
				sourceMode: 0o600, outputMode: 0o600,
				size: size, sha256: digest,
			})
		}
	}
	specs := []phaseInputSpec{
		{name: clientPhase, files: clientFiles},
		{name: peerPhase, files: peerFiles},
	}
	return publishInputCollection(
		layout,
		collectionName,
		func(root string) error {
			return populateLayerAInputCollection(root, specs, builds)
		},
		func(root string) error {
			return validateLayerAInputCollection(root, specs, builds)
		},
	)
}
