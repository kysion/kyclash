package externalpeerhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
)

const (
	startupBudget       = 120 * time.Second
	runnerPollInterval  = 100 * time.Millisecond
	cancelObserveBudget = 15 * time.Second
)

type StartLabRunner struct {
	layout   Layout
	executor CommandExecutor
	clock    RunnerClock
	tart     TartResolver
	entropy  io.Reader

	mu         sync.Mutex
	used       bool
	management *managementStore
	lastWall   time.Time
	lastMono   time.Duration
	haveTime   bool
}

func NewStartLabRunner(
	layout Layout,
	executor CommandExecutor,
	clock RunnerClock,
	tart TartResolver,
	entropy io.Reader,
) (*StartLabRunner, error) {
	if executor == nil || clock == nil || tart == nil || entropy == nil {
		return nil, ErrUnsafeHostCourier
	}
	return &StartLabRunner{
		layout: layout, executor: executor, clock: clock,
		tart: tart, entropy: entropy,
	}, nil
}

func (runner *StartLabRunner) StartLab(ctx context.Context) (runErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runner.mu.Lock()
	if runner.used {
		runner.mu.Unlock()
		return ErrUnsafeHostCourier
	}
	runner.used = true
	runner.mu.Unlock()

	workspace, err := openHostWorkspace(runner.layout)
	if err != nil {
		return err
	}
	defer workspace.close()
	keys, err := loadKeyPair(runner.layout)
	if err != nil {
		return err
	}
	defer keys.close()
	management, err := openManagementStore(runner.layout, workspace.config)
	if err != nil {
		return err
	}
	defer management.close()
	runner.management = management
	defer func() { runner.management = nil }()

	if status, err := runner.readPeerStatus(ctx); err != nil ||
		status.State != "idle-ready" ||
		status.RunID != "" ||
		status.ErrorCode != "" {
		return ErrUnsafeHostCourier
	}
	if err := runner.waitForClientReady(ctx); err != nil {
		return err
	}
	_, startupStart, err := runner.sampleTime()
	if err != nil {
		return err
	}

	clientArtifacts, clientManifest, err := runner.fetchClientBundle(
		ctx,
		startupStart,
	)
	if err != nil {
		return err
	}
	defer clearClientArtifacts(&clientArtifacts, clientManifest)
	if err := workspace.storeClientBundle(clientArtifacts, clientManifest); err != nil {
		return err
	}
	initialInput, clientBlobs, err := workspace.loadInitialInput()
	if err != nil {
		return err
	}
	defer clearBlobs(clientBlobs)
	wall, _, err := runner.sampleTime()
	if err != nil {
		return err
	}
	signer, initial, err := NewTransactionSigner(
		initialInput,
		keys.private,
		wall,
		runner.entropy,
	)
	if err != nil {
		return err
	}
	defer signer.Close()
	defer initial.Clear()
	if keys.revalidate() != nil ||
		workspace.revalidate() != nil ||
		management.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	if err := workspace.storeInitialEnvelopes(initial); err != nil {
		return err
	}

	initialSent := false
	peerSigned := false
	defer func() {
		if runErr == nil || !initialSent {
			return
		}
		cancelContext, cancel := context.WithTimeout(
			context.Background(),
			cancelObserveBudget,
		)
		defer cancel()
		cancelErr := runner.cancelAndObserve(
			cancelContext,
			workspace,
			keys,
			signer,
			peerSigned,
		)
		if cancelErr != nil {
			runErr = errors.Join(runErr, cancelErr)
		}
	}()

	if err := runner.transferInitialToPeer(
		ctx,
		startupStart,
		initialInput,
		initial,
	); err != nil {
		return err
	}
	initialSent = true
	if err := runner.waitForPeerRunning(
		ctx,
		startupStart,
		initial.RunID,
	); err != nil {
		return err
	}
	peerArtifacts, err := runner.fetchPeerBundle(ctx, startupStart)
	if err != nil {
		return err
	}
	defer clearPeerArtifacts(&peerArtifacts)
	if err := workspace.storePeerBundle(peerArtifacts); err != nil {
		return err
	}
	stablePeerArtifacts, peerBlobs, err := workspace.loadPeerArtifacts()
	if err != nil {
		return err
	}
	defer clearBlobs(peerBlobs)
	wall, _, err = runner.sampleTime()
	if err != nil {
		return err
	}
	response, err := signer.SignPeerResponse(
		stablePeerArtifacts,
		wall,
		runner.entropy,
	)
	if err != nil {
		return err
	}
	defer response.Clear()
	peerSigned = true
	if keys.revalidate() != nil ||
		workspace.revalidate() != nil ||
		management.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	if err := workspace.storePeerEnvelope(response); err != nil {
		return err
	}
	if err := runner.transferPeerToClient(
		ctx,
		startupStart,
		initial,
		stablePeerArtifacts,
		response,
	); err != nil {
		return err
	}
	if err := runner.waitForCleanPostflight(
		ctx,
		initial.RunID,
		&startupStart,
	); err != nil {
		return err
	}
	return nil
}

func (runner *StartLabRunner) waitForClientReady(ctx context.Context) error {
	for {
		payload, found, err := runner.runRemote(
			ctx,
			"client",
			filepath.Join(
				vmexternalpeerlab.ClientOutboxRoot,
				vmexternalpeerlab.ClientReadyName,
			),
			remoteActionRead,
			nil,
		)
		if err != nil {
			return err
		}
		if found {
			if len(payload) != 0 {
				clear(payload)
				return ErrUnsafeHostCourier
			}
			clear(payload)
			return nil
		}
		clear(payload)
		if err := runner.clock.Wait(ctx, runnerPollInterval); err != nil {
			return err
		}
	}
}

func (runner *StartLabRunner) fetchClientBundle(
	ctx context.Context,
	start time.Duration,
) (externalpeer.ClientPublicArtifacts, []byte, error) {
	paths := []string{
		filepath.Join(vmexternalpeerlab.ClientOutboxRoot, externalpeer.ClientArtifactNames[0]),
		filepath.Join(vmexternalpeerlab.ClientOutboxRoot, externalpeer.ClientArtifactNames[1]),
		filepath.Join(vmexternalpeerlab.ClientOutboxRoot, externalpeer.ClientArtifactNames[2]),
		filepath.Join(vmexternalpeerlab.ClientOutboxRoot, vmexternalpeerlab.ClientManifestName),
	}
	values := make([][]byte, 0, len(paths))
	for _, path := range paths {
		if err := runner.ensureStartupBudget(start); err != nil {
			clearByteSlices(values)
			return externalpeer.ClientPublicArtifacts{}, nil, err
		}
		payload, found, err := runner.runRemote(
			ctx,
			"client",
			path,
			remoteActionRead,
			nil,
		)
		if err != nil || !found {
			clear(payload)
			clearByteSlices(values)
			return externalpeer.ClientPublicArtifacts{}, nil, ErrUnsafeHostCourier
		}
		values = append(values, payload)
	}
	return externalpeer.ClientPublicArtifacts{
		Descriptor:             values[0],
		TLSClientCSRDER:        values[1],
		OverlayClientPublicKey: values[2],
	}, values[3], nil
}

func (runner *StartLabRunner) transferInitialToPeer(
	ctx context.Context,
	start time.Duration,
	input InitialTransactionInput,
	initial SignedInitialTransaction,
) error {
	values := []struct {
		path string
		data []byte
	}{
		{externalpeer.PeerRunTicketEnvelope, initial.RunTicket},
		{filepath.Join(externalpeer.PeerCourierInbox, externalpeer.ClientArtifactNames[0]), input.ClientArtifacts.Descriptor},
		{filepath.Join(externalpeer.PeerCourierInbox, externalpeer.ClientArtifactNames[1]), input.ClientArtifacts.TLSClientCSRDER},
		{filepath.Join(externalpeer.PeerCourierInbox, externalpeer.ClientArtifactNames[2]), input.ClientArtifacts.OverlayClientPublicKey},
		{externalpeer.PeerClientTransferManifest, input.ClientManifest},
		{externalpeer.PeerClientEnvelope, initial.ClientToPeer},
		{externalpeer.PeerWakeTrigger, nil},
	}
	for _, value := range values {
		if err := runner.ensureStartupBudget(start); err != nil {
			return err
		}
		payload, _, err := runner.runRemote(
			ctx,
			"peer",
			value.path,
			remoteActionCreate,
			value.data,
		)
		clear(payload)
		if err != nil {
			return err
		}
	}
	return nil
}

func (runner *StartLabRunner) waitForPeerRunning(
	ctx context.Context,
	start time.Duration,
	runID string,
) error {
	for {
		if err := runner.ensureStartupBudget(start); err != nil {
			return err
		}
		status, err := runner.readPeerStatus(ctx)
		if err != nil {
			return err
		}
		if status.ErrorCode != "" || status.State == "recovery-only" {
			return ErrUnsafeHostCourier
		}
		switch status.State {
		case "starting":
			if status.RunID != runID {
				return ErrUnsafeHostCourier
			}
		case "running":
			if status.RunID != runID {
				return ErrUnsafeHostCourier
			}
			return nil
		default:
			return ErrUnsafeHostCourier
		}
		if err := runner.clock.Wait(ctx, runnerPollInterval); err != nil {
			return err
		}
	}
}

func (runner *StartLabRunner) fetchPeerBundle(
	ctx context.Context,
	start time.Duration,
) (externalpeer.PeerPublicArtifacts, error) {
	values := make([][]byte, 0, len(externalpeer.PeerArtifactNames))
	for _, name := range externalpeer.PeerArtifactNames {
		if err := runner.ensureStartupBudget(start); err != nil {
			clearByteSlices(values)
			return externalpeer.PeerPublicArtifacts{}, err
		}
		payload, found, err := runner.runRemote(
			ctx,
			"peer",
			filepath.Join(externalpeer.PeerPublicOutbox, name),
			remoteActionRead,
			nil,
		)
		if err != nil || !found {
			clear(payload)
			clearByteSlices(values)
			return externalpeer.PeerPublicArtifacts{}, ErrUnsafeHostCourier
		}
		values = append(values, payload)
	}
	return externalpeer.PeerPublicArtifacts{
		Descriptor:             values[0],
		CADER:                  values[1],
		ServerCertificateDER:   values[2],
		ClientCertificateDER:   values[3],
		OverlayServerPublicKey: values[4],
		SystemSSHHostPublicKey: values[5],
		TransferManifest:       values[6],
	}, nil
}

func (runner *StartLabRunner) transferPeerToClient(
	ctx context.Context,
	start time.Duration,
	initial SignedInitialTransaction,
	artifacts externalpeer.PeerPublicArtifacts,
	response SignedPeerResponse,
) error {
	values := []struct {
		name string
		data []byte
	}{
		{vmexternalpeerlab.RunTicketName, initial.RunTicket},
		{vmexternalpeerlab.ClientEnvelopeName, initial.ClientToPeer},
		{externalpeer.PeerArtifactNames[0], artifacts.Descriptor},
		{externalpeer.PeerArtifactNames[1], artifacts.CADER},
		{externalpeer.PeerArtifactNames[2], artifacts.ServerCertificateDER},
		{externalpeer.PeerArtifactNames[3], artifacts.ClientCertificateDER},
		{externalpeer.PeerArtifactNames[4], artifacts.OverlayServerPublicKey},
		{externalpeer.PeerArtifactNames[5], artifacts.SystemSSHHostPublicKey},
		{externalpeer.PeerArtifactNames[6], artifacts.TransferManifest},
		{vmexternalpeerlab.PeerEnvelopeName, response.PeerToClient},
		{vmexternalpeerlab.PeerReadyName, nil},
	}
	for _, value := range values {
		if err := runner.ensureStartupBudget(start); err != nil {
			return err
		}
		payload, _, err := runner.runRemote(
			ctx,
			"client",
			filepath.Join(vmexternalpeerlab.ClientInboxRoot, value.name),
			remoteActionCreate,
			value.data,
		)
		clear(payload)
		if err != nil {
			return err
		}
	}
	return nil
}

func (runner *StartLabRunner) cancelAndObserve(
	ctx context.Context,
	workspace *hostWorkspace,
	keys *loadedKeyPair,
	signer *TransactionSigner,
	peerSigned bool,
) error {
	wall, _, err := runner.sampleTime()
	if err != nil {
		return err
	}
	cancellation, err := signer.SignCancellation(wall, runner.entropy)
	if err != nil {
		return err
	}
	defer cancellation.Clear()
	if keys.revalidate() != nil ||
		workspace.revalidate() != nil ||
		runner.management.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	if err := workspace.storeCancelEnvelope(cancellation); err != nil {
		return err
	}
	for _, value := range []struct {
		path string
		data []byte
	}{
		{externalpeer.PeerCancelEnvelope, cancellation.Cancel},
		{externalpeer.PeerCancelTrigger, nil},
	} {
		payload, _, err := runner.runRemote(
			ctx,
			"peer",
			value.path,
			remoteActionCreate,
			value.data,
		)
		clear(payload)
		if err != nil {
			return err
		}
	}
	if peerSigned {
		// Sequence 2 remains retained for the client branch; sequence 3 is
		// delivered only to the peer supervisor.
	}
	return runner.waitForCleanPostflight(ctx, signer.initial.RunID, nil)
}

func (runner *StartLabRunner) waitForCleanPostflight(
	ctx context.Context,
	runID string,
	start *time.Duration,
) error {
	for {
		if start != nil {
			if err := runner.ensureStartupBudget(*start); err != nil {
				return err
			}
		}
		status, err := runner.readPeerStatus(ctx)
		if err != nil {
			return err
		}
		if status.State == "clean-postflight" {
			if status.RunID != runID || status.ErrorCode != "" {
				return ErrUnsafeHostCourier
			}
			return nil
		}
		if status.State != "running" &&
			status.State != "starting" {
			return ErrUnsafeHostCourier
		}
		if status.RunID != runID || status.ErrorCode != "" {
			return ErrUnsafeHostCourier
		}
		if err := runner.clock.Wait(ctx, runnerPollInterval); err != nil {
			return err
		}
	}
}

func (runner *StartLabRunner) readPeerStatus(
	ctx context.Context,
) (externalpeer.PeerSupervisorStatus, error) {
	payload, found, err := runner.runRemote(
		ctx,
		"peer",
		externalpeer.PeerPublicStatus,
		remoteActionRead,
		nil,
	)
	if err != nil || !found {
		clear(payload)
		return externalpeer.PeerSupervisorStatus{}, ErrUnsafeHostCourier
	}
	defer clear(payload)
	return decodePeerStatus(payload)
}

func decodePeerStatus(
	data []byte,
) (externalpeer.PeerSupervisorStatus, error) {
	if len(data) == 0 || len(data) > 1024 {
		return externalpeer.PeerSupervisorStatus{}, ErrUnsafeHostCourier
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var status externalpeer.PeerSupervisorStatus
	if err := decoder.Decode(&status); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return externalpeer.PeerSupervisorStatus{}, ErrUnsafeHostCourier
	}
	canonical, err := json.Marshal(status)
	if err != nil {
		return externalpeer.PeerSupervisorStatus{}, ErrUnsafeHostCourier
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) ||
		status.SchemaVersion != externalpeer.SchemaVersion {
		return externalpeer.PeerSupervisorStatus{}, ErrUnsafeHostCourier
	}
	return status, nil
}

func (runner *StartLabRunner) sampleTime() (
	time.Time,
	time.Duration,
	error,
) {
	wall := runner.clock.WallNow().UTC()
	monotonic := runner.clock.MonotonicNow()
	if wall.IsZero() || monotonic < 0 ||
		runner.haveTime &&
			(monotonic < runner.lastMono || wall.Before(runner.lastWall)) {
		return time.Time{}, 0, ErrUnsafeHostCourier
	}
	runner.lastWall = wall
	runner.lastMono = monotonic
	runner.haveTime = true
	return wall, monotonic, nil
}

func (runner *StartLabRunner) ensureStartupBudget(start time.Duration) error {
	_, current, err := runner.sampleTime()
	if err != nil {
		return err
	}
	if current < start || current-start >= startupBudget {
		return context.DeadlineExceeded
	}
	return nil
}

func clearClientArtifacts(
	artifacts *externalpeer.ClientPublicArtifacts,
	manifest []byte,
) {
	if artifacts != nil {
		clear(artifacts.Descriptor)
		clear(artifacts.TLSClientCSRDER)
		clear(artifacts.OverlayClientPublicKey)
		*artifacts = externalpeer.ClientPublicArtifacts{}
	}
	clear(manifest)
}

func clearPeerArtifacts(artifacts *externalpeer.PeerPublicArtifacts) {
	if artifacts == nil {
		return
	}
	clear(artifacts.Descriptor)
	clear(artifacts.CADER)
	clear(artifacts.ServerCertificateDER)
	clear(artifacts.ClientCertificateDER)
	clear(artifacts.OverlayServerPublicKey)
	clear(artifacts.SystemSSHHostPublicKey)
	clear(artifacts.TransferManifest)
	*artifacts = externalpeer.PeerPublicArtifacts{}
}

func clearByteSlices(values [][]byte) {
	for _, value := range values {
		clear(value)
	}
}

var _ FixedTransferRunner = (*StartLabRunner)(nil)
