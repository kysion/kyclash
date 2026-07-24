package externalpeerhost

import (
	"os"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
)

type hostWorkspace struct {
	layout      Layout
	workspace   *secureDirectory
	control     *secureDirectory
	client      *secureDirectory
	peer        *secureDirectory
	envelopes   *secureDirectory
	config      externalpeer.PeerSupervisorConfig
	expectation externalpeer.RunTicketExpectation
	controlData []secureBlob
}

func openHostWorkspace(layout Layout) (*hostWorkspace, error) {
	uid := uint32(os.Getuid())
	workspace, err := openSecureDirectory(layout.Workspace, uid)
	if err != nil {
		return nil, err
	}
	control, err := openSecureDirectory(layout.Control, uid)
	if err != nil {
		_ = workspace.close()
		return nil, err
	}
	client, err := openSecureDirectory(layout.ClientPublic, uid)
	if err != nil {
		_ = control.close()
		_ = workspace.close()
		return nil, err
	}
	peer, err := openSecureDirectory(layout.PeerPublic, uid)
	if err != nil {
		_ = client.close()
		_ = control.close()
		_ = workspace.close()
		return nil, err
	}
	envelopes, err := openSecureDirectory(layout.Envelopes, uid)
	if err != nil {
		_ = peer.close()
		_ = client.close()
		_ = control.close()
		_ = workspace.close()
		return nil, err
	}
	result := &hostWorkspace{
		layout: layout, workspace: workspace, control: control,
		client: client, peer: peer, envelopes: envelopes,
	}
	fail := func() (*hostWorkspace, error) {
		result.close()
		return nil, ErrUnsafeHostCourier
	}
	if workspace.requireExactNames([]string{
		ControlDirectoryName,
		ClientDirectoryName,
		PeerDirectoryName,
		EnvelopeDirectoryName,
	}) != nil ||
		control.requireExactNames(controlInputNames) != nil ||
		client.requireExactNames(nil) != nil ||
		peer.requireExactNames(nil) != nil ||
		envelopes.requireExactNames(nil) != nil {
		return fail()
	}
	configBlob, err := control.readStableFile(
		PeerConfigName,
		externalpeer.MaxDescriptorSize,
		nil,
	)
	if err != nil {
		return fail()
	}
	expectationBlob, err := control.readStableFile(
		TicketExpectationName,
		externalpeer.MaxDescriptorSize,
		nil,
	)
	if err != nil {
		clear(configBlob.bytes)
		return fail()
	}
	result.controlData = []secureBlob{configBlob, expectationBlob}
	result.config, err = externalpeer.DecodePeerSupervisorConfig(configBlob.bytes)
	if err != nil {
		return fail()
	}
	result.expectation, err = externalpeer.DecodeRunTicketExpectation(
		expectationBlob.bytes,
	)
	if err != nil {
		return fail()
	}
	if result.revalidate() != nil {
		return fail()
	}
	return result, nil
}

func (workspace *hostWorkspace) close() {
	if workspace == nil {
		return
	}
	for index := range workspace.controlData {
		clear(workspace.controlData[index].bytes)
	}
	for _, directory := range []*secureDirectory{
		workspace.envelopes,
		workspace.peer,
		workspace.client,
		workspace.control,
		workspace.workspace,
	} {
		_ = directory.close()
	}
	*workspace = hostWorkspace{}
}

func (workspace *hostWorkspace) revalidate() error {
	if workspace == nil {
		return ErrUnsafeHostCourier
	}
	for _, blob := range workspace.controlData {
		if blob.witness.revalidate() != nil {
			return ErrUnsafeHostCourier
		}
	}
	for _, directory := range []*secureDirectory{
		workspace.workspace,
		workspace.control,
		workspace.client,
		workspace.peer,
		workspace.envelopes,
	} {
		if directory == nil || directory.revalidate() != nil {
			return ErrUnsafeHostCourier
		}
	}
	return nil
}

func (workspace *hostWorkspace) storeClientBundle(
	artifacts externalpeer.ClientPublicArtifacts,
	manifest []byte,
) error {
	if workspace == nil ||
		workspace.client.requireExactNames(nil) != nil ||
		workspace.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	payloads := [][]byte{
		artifacts.Descriptor,
		artifacts.TLSClientCSRDER,
		artifacts.OverlayClientPublicKey,
		manifest,
	}
	for index, name := range clientInputNames {
		if _, err := workspace.client.createExactFile(name, payloads[index]); err != nil {
			return err
		}
	}
	if workspace.client.requireExactNames(clientInputNames) != nil {
		return ErrUnsafeHostCourier
	}
	return workspace.revalidate()
}

func (workspace *hostWorkspace) loadInitialInput() (
	InitialTransactionInput,
	[]secureBlob,
	error,
) {
	if workspace == nil ||
		workspace.client.requireExactNames(clientInputNames) != nil ||
		workspace.revalidate() != nil {
		return InitialTransactionInput{}, nil, ErrUnsafeHostCourier
	}
	blobs := make([]secureBlob, 0, len(clientInputNames))
	for index, name := range clientInputNames {
		maximum := externalpeer.MaxArtifactSize
		if index == 0 || index == len(clientInputNames)-1 {
			maximum = externalpeer.MaxDescriptorSize
		}
		blob, err := workspace.client.readStableFile(name, maximum, nil)
		if err != nil {
			clearBlobs(blobs)
			return InitialTransactionInput{}, nil, err
		}
		blobs = append(blobs, blob)
	}
	return InitialTransactionInput{
		Config:            workspace.config,
		TicketExpectation: workspace.expectation,
		ClientArtifacts: externalpeer.ClientPublicArtifacts{
			Descriptor:             blobs[0].bytes,
			TLSClientCSRDER:        blobs[1].bytes,
			OverlayClientPublicKey: blobs[2].bytes,
		},
		ClientManifest: blobs[3].bytes,
	}, blobs, nil
}

func (workspace *hostWorkspace) storeInitialEnvelopes(
	initial SignedInitialTransaction,
) error {
	if workspace == nil ||
		workspace.envelopes.requireExactNames(nil) != nil ||
		workspace.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	if _, err := workspace.envelopes.createExactFile(
		RunTicketEnvelopeName,
		initial.RunTicket,
	); err != nil {
		return err
	}
	if _, err := workspace.envelopes.createExactFile(
		ClientEnvelopeName,
		initial.ClientToPeer,
	); err != nil {
		return err
	}
	if workspace.envelopes.requireExactNames(signedEnvelopeNames) != nil {
		return ErrUnsafeHostCourier
	}
	return workspace.revalidate()
}

func (workspace *hostWorkspace) storePeerBundle(
	artifacts externalpeer.PeerPublicArtifacts,
) error {
	if workspace == nil ||
		workspace.peer.requireExactNames(nil) != nil ||
		workspace.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	payloads := [][]byte{
		artifacts.Descriptor,
		artifacts.CADER,
		artifacts.ServerCertificateDER,
		artifacts.ClientCertificateDER,
		artifacts.OverlayServerPublicKey,
		artifacts.SystemSSHHostPublicKey,
		artifacts.TransferManifest,
	}
	for index, name := range peerInputNames {
		if _, err := workspace.peer.createExactFile(name, payloads[index]); err != nil {
			return err
		}
	}
	if workspace.peer.requireExactNames(peerInputNames) != nil {
		return ErrUnsafeHostCourier
	}
	return workspace.revalidate()
}

func (workspace *hostWorkspace) loadPeerArtifacts() (
	externalpeer.PeerPublicArtifacts,
	[]secureBlob,
	error,
) {
	if workspace == nil ||
		workspace.peer.requireExactNames(peerInputNames) != nil ||
		workspace.revalidate() != nil {
		return externalpeer.PeerPublicArtifacts{}, nil, ErrUnsafeHostCourier
	}
	blobs := make([]secureBlob, 0, len(peerInputNames))
	for index, name := range peerInputNames {
		maximum := externalpeer.MaxArtifactSize
		if index == 0 || index == len(peerInputNames)-1 {
			maximum = externalpeer.MaxDescriptorSize
		}
		blob, err := workspace.peer.readStableFile(name, maximum, nil)
		if err != nil {
			clearBlobs(blobs)
			return externalpeer.PeerPublicArtifacts{}, nil, err
		}
		blobs = append(blobs, blob)
	}
	return externalpeer.PeerPublicArtifacts{
		Descriptor:             blobs[0].bytes,
		CADER:                  blobs[1].bytes,
		ServerCertificateDER:   blobs[2].bytes,
		ClientCertificateDER:   blobs[3].bytes,
		OverlayServerPublicKey: blobs[4].bytes,
		SystemSSHHostPublicKey: blobs[5].bytes,
		TransferManifest:       blobs[6].bytes,
	}, blobs, nil
}

func (workspace *hostWorkspace) storePeerEnvelope(
	response SignedPeerResponse,
) error {
	if workspace == nil ||
		workspace.envelopes.requireExactNames(signedEnvelopeNames) != nil ||
		workspace.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	if _, err := workspace.envelopes.createExactFile(
		PeerEnvelopeName,
		response.PeerToClient,
	); err != nil {
		return err
	}
	if workspace.envelopes.requireExactNames(successEnvelopeNames) != nil {
		return ErrUnsafeHostCourier
	}
	return workspace.revalidate()
}

func (workspace *hostWorkspace) storeCancelEnvelope(
	cancellation SignedCancellation,
) error {
	if workspace == nil || workspace.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	before := signedEnvelopeNames
	after := cancelEnvelopeNames
	if workspace.envelopes.requireExactNames(before) != nil {
		before = successEnvelopeNames
		after = successCancelEnvelopeNames
		if workspace.envelopes.requireExactNames(before) != nil {
			return ErrUnsafeHostCourier
		}
	}
	if _, err := workspace.envelopes.createExactFile(
		CancelEnvelopeName,
		cancellation.Cancel,
	); err != nil {
		return err
	}
	if workspace.envelopes.requireExactNames(after) != nil {
		return ErrUnsafeHostCourier
	}
	return workspace.revalidate()
}

func clearBlobs(blobs []secureBlob) {
	for index := range blobs {
		clear(blobs[index].bytes)
	}
}
