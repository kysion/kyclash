package externalpeerhost

import (
	"bytes"
	"context"
	"os"
	"path/filepath"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/externalpeergueststaging"
)

var listenerApprovalNames = []string{
	ClientApprovedBaselineName,
	PeerApprovedBaselineName,
	BaselineApprovalWitnessName,
}

type baselineApprovalWitness struct {
	SchemaVersion         uint8  `json:"schema_version"`
	ConfigSHA256          string `json:"config_sha256"`
	ExpectationSHA256     string `json:"expectation_sha256"`
	CourierKeySHA256      string `json:"courier_public_key_sha256"`
	ClientIdentitySHA256  string `json:"client_identity_sha256"`
	ClientInventorySHA256 string `json:"client_inventory_sha256"`
	ClientCandidateSHA256 string `json:"client_candidate_sha256"`
	ClientReviewSHA256    string `json:"client_review_sha256"`
	PeerIdentitySHA256    string `json:"peer_identity_sha256"`
	PeerInventorySHA256   string `json:"peer_inventory_sha256"`
	PeerCandidateSHA256   string `json:"peer_candidate_sha256"`
	PeerReviewSHA256      string `json:"peer_review_sha256"`
}

type approvedListenerBaselines struct {
	directory  *secureDirectory
	client     secureBlob
	peer       secureBlob
	witness    secureBlob
	clientPath string
	peerPath   string
}

// ApproveLayerBListenerBaselines is the explicit, no-argument reviewer
// boundary between guest candidate review and guest pin-input publication.
// It never creates known_hosts and never publishes Layer-B pin inputs.
func ApproveLayerBListenerBaselines(
	ctx context.Context,
	layout Layout,
	executor CommandExecutor,
	clock RunnerClock,
	tart TartResolver,
) error {
	if ctx == nil || executor == nil || clock == nil || tart == nil {
		return ErrUnsafeHostCourier
	}
	builds, err := loadExternalPeerBuildInputs(layout)
	if err != nil {
		return err
	}
	courierPublic, managementPublic, err := loadPublicInputKeys(layout)
	if err != nil {
		return err
	}
	defer clear(courierPublic)
	defer clearByteSlices(managementPublic)
	if requirePublishedLayerAInputs(
		layout,
		builds,
		managementPublic,
	) != nil {
		return ErrUnsafeHostCourier
	}
	client, err := openGuestReviewSet(
		layout,
		"client",
		builds,
		managementPublic[0],
	)
	if err != nil {
		return err
	}
	defer client.close()
	peer, err := openGuestReviewSet(
		layout,
		"peer",
		builds,
		managementPublic[1],
	)
	if err != nil {
		return err
	}
	defer peer.close()
	if !client.prepared() || !peer.prepared() {
		return ErrUnsafeHostCourier
	}
	workspace, err := openHostWorkspace(layout)
	if err != nil {
		return err
	}
	defer workspace.close()
	if len(workspace.controlData) != 2 {
		return ErrUnsafeHostCourier
	}
	configBytes := workspace.controlData[0].bytes
	expectationBytes := workspace.controlData[1].bytes
	expected, expectedBytes, err := buildRunTicketExpectation(
		builds,
		configBytes,
	)
	if err != nil {
		return err
	}
	defer clear(expectedBytes)
	if !bytes.Equal(expectedBytes, expectationBytes) ||
		!equalExpectation(expected, workspace.expectation) {
		return ErrUnsafeHostCourier
	}
	if err := ensureManagementReview(layout, client, peer); err != nil {
		return err
	}
	management, err := openPinnedManagementStore(
		layout,
		workspace.config,
	)
	if err != nil {
		return err
	}
	defer management.close()
	clientIP, err := resolveLayerBAddress(
		ctx,
		layout,
		executor,
		tart,
		"client",
		externalpeer.ClientVMName,
	)
	if err != nil || clientIP.String() != workspace.config.Client.IPv4 {
		return ErrUnsafeHostCourier
	}
	peerIP, err := resolveLayerBAddress(
		ctx,
		layout,
		executor,
		tart,
		"peer",
		externalpeer.PeerVMName,
	)
	if err != nil || peerIP.String() != workspace.config.Peer.IPv4 {
		return ErrUnsafeHostCourier
	}
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
		return err
	}
	if err := validatePreparedGuestReviews(
		client,
		peer,
		workspace.config,
		configBytes,
		workspace.expectation,
		expectationBytes,
		courierPublic,
	); err != nil {
		return err
	}
	return publishListenerBaselineApproval(
		layout,
		client,
		peer,
		configBytes,
		expectationBytes,
		courierPublic,
	)
}

func publishListenerBaselineApproval(
	layout Layout,
	client *guestReviewSet,
	peer *guestReviewSet,
	config []byte,
	expectation []byte,
	courierPublic []byte,
) error {
	witness, witnessBytes, err := expectedBaselineApprovalWitness(
		client,
		peer,
		config,
		expectation,
		courierPublic,
	)
	if err != nil {
		return err
	}
	defer clear(witnessBytes)
	copySpecs := []publicFileSpec{
		approvalBaselineSpec(
			client,
			ClientApprovedBaselineName,
		),
		approvalBaselineSpec(
			peer,
			PeerApprovedBaselineName,
		),
	}
	for _, value := range copySpecs {
		if value.source == "" || value.size == 0 ||
			!validLowerSHA256(value.sha256) {
			return ErrUnsafeHostCourier
		}
	}
	validate := func(root string) error {
		if requireExactPrivateDirectory(root, listenerApprovalNames) != nil {
			return ErrUnsafeHostCourier
		}
		for _, value := range copySpecs {
			digest, size, err := hashStableFile(
				filepath.Join(root, value.name),
				uint32(os.Getuid()),
				secureFileMode,
				externalpeer.MaxChildControlFrame,
			)
			if err != nil || digest != value.sha256 ||
				size != value.size {
				return ErrUnsafeHostCourier
			}
		}
		data, err := readOwnedRegularFile(
			filepath.Join(root, BaselineApprovalWitnessName),
			secureFileMode,
			externalpeer.MaxDescriptorSize,
		)
		if err != nil || !bytes.Equal(data, witnessBytes) {
			clear(data)
			return ErrUnsafeHostCourier
		}
		defer clear(data)
		var decoded baselineApprovalWitness
		if decodeCanonicalHostJSON(data, &decoded) != nil ||
			decoded != witness {
			return ErrUnsafeHostCourier
		}
		return nil
	}
	populate := func(root string) error {
		if client.revalidate() != nil || peer.revalidate() != nil {
			return ErrUnsafeHostCourier
		}
		for _, value := range copySpecs {
			if err := copyStablePublicFile(
				value.source,
				filepath.Join(root, value.name),
				value.sourceMode,
				value.outputMode,
				value.size,
				value.sha256,
			); err != nil {
				return err
			}
		}
		directory, err := openSecureDirectory(
			root,
			uint32(os.Getuid()),
		)
		if err != nil {
			return err
		}
		defer directory.close()
		if _, err := directory.createExactFile(
			BaselineApprovalWitnessName,
			witnessBytes,
		); err != nil {
			return err
		}
		return syncDirectoryPath(root)
	}
	return publishPrivateDirectory(
		layout.PrivateRoot,
		layout.ListenerApproval,
		ListenerApprovalName,
		populate,
		validate,
	)
}

func loadApprovedListenerBaselines(
	layout Layout,
	client *guestReviewSet,
	peer *guestReviewSet,
	config []byte,
	expectation []byte,
	courierPublic []byte,
) (*approvedListenerBaselines, error) {
	if pathAbsent(layout.ListenerApproval) {
		return nil, nil
	}
	directory, err := openSecureDirectory(
		layout.ListenerApproval,
		uint32(os.Getuid()),
	)
	if err != nil {
		return nil, err
	}
	result := &approvedListenerBaselines{directory: directory}
	fail := func() (*approvedListenerBaselines, error) {
		result.close()
		return nil, ErrUnsafeHostCourier
	}
	if directory.requireExactNames(listenerApprovalNames) != nil {
		return fail()
	}
	result.client, err = directory.readStableFile(
		ClientApprovedBaselineName,
		externalpeer.MaxChildControlFrame,
		nil,
	)
	if err != nil {
		return fail()
	}
	result.peer, err = directory.readStableFile(
		PeerApprovedBaselineName,
		externalpeer.MaxChildControlFrame,
		nil,
	)
	if err != nil {
		return fail()
	}
	result.witness, err = directory.readStableFile(
		BaselineApprovalWitnessName,
		externalpeer.MaxDescriptorSize,
		nil,
	)
	if err != nil {
		return fail()
	}
	_, expectedBytes, err := expectedBaselineApprovalWitness(
		client,
		peer,
		config,
		expectation,
		courierPublic,
	)
	if err != nil {
		clear(expectedBytes)
		return fail()
	}
	defer clear(expectedBytes)
	clientCandidate, err := client.blob(
		externalpeergueststaging.BaselineCandidateName,
	)
	if err != nil {
		return fail()
	}
	peerCandidate, err := peer.blob(
		externalpeergueststaging.BaselineCandidateName,
	)
	if err != nil ||
		!bytes.Equal(result.client.bytes, clientCandidate.bytes) ||
		!bytes.Equal(result.peer.bytes, peerCandidate.bytes) ||
		!bytes.Equal(result.witness.bytes, expectedBytes) {
		return fail()
	}
	result.clientPath = filepath.Join(
		layout.ListenerApproval,
		ClientApprovedBaselineName,
	)
	result.peerPath = filepath.Join(
		layout.ListenerApproval,
		PeerApprovedBaselineName,
	)
	return result, nil
}

func (value *approvedListenerBaselines) close() {
	if value == nil {
		return
	}
	clear(value.client.bytes)
	clear(value.peer.bytes)
	clear(value.witness.bytes)
	_ = value.directory.close()
	*value = approvedListenerBaselines{}
}

func approvalBaselineSpec(
	review *guestReviewSet,
	name string,
) publicFileSpec {
	blob, err := review.blob(
		externalpeergueststaging.BaselineCandidateName,
	)
	if err != nil {
		return publicFileSpec{}
	}
	return publicFileSpec{
		name: name,
		source: filepath.Join(
			review.root,
			externalpeergueststaging.BaselineCandidateName,
		),
		sourceMode: secureFileMode,
		outputMode: secureFileMode,
		size:       uint64(len(blob.bytes)),
		sha256:     hashBytes(blob.bytes),
	}
}

func expectedBaselineApprovalWitness(
	client *guestReviewSet,
	peer *guestReviewSet,
	config []byte,
	expectation []byte,
	courierPublic []byte,
) (baselineApprovalWitness, []byte, error) {
	if client == nil || peer == nil ||
		!client.prepared() || !peer.prepared() ||
		client.revalidate() != nil || peer.revalidate() != nil {
		return baselineApprovalWitness{}, nil, ErrUnsafeHostCourier
	}
	digest := func(
		review *guestReviewSet,
		name string,
	) (string, error) {
		blob, err := review.blob(name)
		if err != nil {
			return "", err
		}
		return hashBytes(blob.bytes), nil
	}
	clientIdentity, err := digest(
		client,
		externalpeergueststaging.VMIdentityWitnessName,
	)
	if err != nil {
		return baselineApprovalWitness{}, nil, err
	}
	clientInventory, err := digest(
		client,
		externalpeergueststaging.ListenerInventoryName,
	)
	if err != nil {
		return baselineApprovalWitness{}, nil, err
	}
	clientCandidate, err := digest(
		client,
		externalpeergueststaging.BaselineCandidateName,
	)
	if err != nil {
		return baselineApprovalWitness{}, nil, err
	}
	clientReview, err := digest(
		client,
		externalpeergueststaging.ReviewWitnessName,
	)
	if err != nil {
		return baselineApprovalWitness{}, nil, err
	}
	peerIdentity, err := digest(
		peer,
		externalpeergueststaging.VMIdentityWitnessName,
	)
	if err != nil {
		return baselineApprovalWitness{}, nil, err
	}
	peerInventory, err := digest(
		peer,
		externalpeergueststaging.ListenerInventoryName,
	)
	if err != nil {
		return baselineApprovalWitness{}, nil, err
	}
	peerCandidate, err := digest(
		peer,
		externalpeergueststaging.BaselineCandidateName,
	)
	if err != nil {
		return baselineApprovalWitness{}, nil, err
	}
	peerReview, err := digest(
		peer,
		externalpeergueststaging.ReviewWitnessName,
	)
	if err != nil {
		return baselineApprovalWitness{}, nil, err
	}
	value := baselineApprovalWitness{
		SchemaVersion:         1,
		ConfigSHA256:          hashBytes(config),
		ExpectationSHA256:     hashBytes(expectation),
		CourierKeySHA256:      hashBytes(courierPublic),
		ClientIdentitySHA256:  clientIdentity,
		ClientInventorySHA256: clientInventory,
		ClientCandidateSHA256: clientCandidate,
		ClientReviewSHA256:    clientReview,
		PeerIdentitySHA256:    peerIdentity,
		PeerInventorySHA256:   peerInventory,
		PeerCandidateSHA256:   peerCandidate,
		PeerReviewSHA256:      peerReview,
	}
	encoded, err := encodeCanonicalHostJSON(value)
	if err != nil {
		return baselineApprovalWitness{}, nil, err
	}
	return value, encoded, nil
}
