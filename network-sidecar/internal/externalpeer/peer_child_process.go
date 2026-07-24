package externalpeer

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type PeerChildReady struct {
	Descriptor PeerPublicDescriptor
	Artifacts  PeerPublicArtifacts
	RunNonce   []byte
}

type childReadResult struct {
	data []byte
	err  error
}

type PeerChildProcess struct {
	mu             sync.Mutex
	command        *exec.Cmd
	stdin          io.WriteCloser
	responses      <-chan childReadResult
	identity       ChildIdentity
	done           chan error
	closed         bool
	protocolFailed bool
}

func StartPeerChildProcess(
	ctx context.Context,
	config PeerSupervisorConfig,
	expectedChild StagedFile,
	peerConfig PeerConfig,
	clientDescriptor ClientPublicDescriptor,
	onBound func(ChildIdentity) error,
) (*PeerChildProcess, PeerChildReady, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if config.Validate() != nil ||
		expectedChild.Path != PeerChildPath ||
		validateStagedFile(expectedChild) != nil ||
		validatePeerConfig(peerConfig) != nil ||
		clientDescriptor.RunID != peerConfig.RunID ||
		onBound == nil {
		return nil, PeerChildReady{}, ErrSupervisorState
	}
	bootstrap, err := encodeChildBootstrap(peerConfig)
	if err != nil {
		return nil, PeerChildReady{}, err
	}
	defer clear(bootstrap)
	command := exec.Command(PeerChildPath)
	command.Args = []string{PeerChildPath}
	command.Env = []string{}
	command.Dir = "/"
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: config.PeerChildUID,
			Gid: config.PeerChildGID,
		},
		Setsid: true,
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, PeerChildReady{}, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, PeerChildReady{}, err
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		return nil, PeerChildReady{}, err
	}
	responses := make(chan childReadResult, 1)
	process := &PeerChildProcess{
		command:   command,
		stdin:     stdin,
		responses: responses,
		done:      make(chan error, 1),
	}
	go scanPeerChildResponses(stdout, responses)
	go func() {
		process.done <- command.Wait()
		close(process.done)
	}()
	identity, err := bindStartedChildIdentity(
		command.Process.Pid,
		peerConfig.RunID,
		config.PeerChildUID,
	)
	if err != nil {
		_ = process.killUnboundStartedChild()
		return nil, PeerChildReady{}, err
	}
	process.identity = identity
	if identity.Path != expectedChild.Path ||
		identity.Device != expectedChild.Device ||
		identity.Inode != expectedChild.Inode ||
		identity.SHA256 != expectedChild.SHA256 {
		_ = process.terminateBoundChild()
		return nil, PeerChildReady{}, ErrSupervisorRecovery
	}
	// Persist the exact PID/start/path/dev/inode/hash/session identity before
	// bootstrap bytes can create any listener or public artifact. If the
	// durable journal update fails, reap the still-bound child immediately.
	if err := onBound(identity); err != nil {
		_ = process.terminateBoundChild()
		return nil, PeerChildReady{}, err
	}
	if _, err := stdin.Write(bootstrap); err != nil {
		_ = process.Stop(context.Background())
		return nil, PeerChildReady{}, err
	}
	response, err := process.readResponse(ctx, 120*time.Second)
	if err != nil {
		_ = process.Stop(context.Background())
		return nil, PeerChildReady{}, err
	}
	ready, err := decodePeerChildReady(response, peerConfig, clientDescriptor)
	if err != nil {
		_ = process.Stop(context.Background())
		return nil, PeerChildReady{}, err
	}
	return process, ready, nil
}

func (process *PeerChildProcess) Identity() ChildIdentity {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.identity
}

func (process *PeerChildProcess) Control(
	ctx context.Context,
	command string,
) (ChildResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.closed ||
		process.protocolFailed ||
		command != "status" &&
			command != "block_quic_udp" &&
			command != "refuse_wss" {
		return ChildResponse{}, ErrSupervisorState
	}
	encoded, err := json.Marshal(ChildCommand{Command: command})
	if err != nil {
		return ChildResponse{}, ErrSupervisorState
	}
	encoded = append(encoded, '\n')
	if _, err := process.stdin.Write(encoded); err != nil {
		clear(encoded)
		return ChildResponse{}, err
	}
	clear(encoded)
	return process.readResponseLocked(ctx, 10*time.Second)
}

func (process *PeerChildProcess) Stop(ctx context.Context) error {
	if process == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	process.mu.Lock()
	if process.closed {
		process.mu.Unlock()
		return nil
	}
	process.closed = true
	var writeErr error
	if !process.protocolFailed {
		encoded := []byte("{\"command\":\"stop\"}\n")
		_, writeErr = process.stdin.Write(encoded)
		clear(encoded)
	}
	_ = process.stdin.Close()
	if writeErr == nil && !process.protocolFailed {
		_, _ = process.readResponseLocked(ctx, 5*time.Second)
	}
	process.mu.Unlock()
	waitContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case err := <-process.done:
		if err != nil {
			return err
		}
		return nil
	case <-waitContext.Done():
		return process.terminateBoundChild()
	}
}

func (process *PeerChildProcess) Done() <-chan error { return process.done }

func (process *PeerChildProcess) readResponse(
	ctx context.Context,
	timeout time.Duration,
) (ChildResponse, error) {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.readResponseLocked(ctx, timeout)
}

func (process *PeerChildProcess) readResponseLocked(
	ctx context.Context,
	timeout time.Duration,
) (ChildResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case value, ok := <-process.responses:
		if !ok {
			process.protocolFailed = true
			return ChildResponse{}, io.EOF
		}
		if value.err != nil {
			process.protocolFailed = true
			return ChildResponse{}, value.err
		}
		defer clear(value.data)
		var response ChildResponse
		if err := strictDecode(value.data, &response); err != nil ||
			response.SchemaVersion != SchemaVersion {
			process.protocolFailed = true
			_ = process.stdin.Close()
			return ChildResponse{}, ErrSupervisorState
		}
		return response, nil
	case <-ctx.Done():
		process.protocolFailed = true
		_ = process.stdin.Close()
		return ChildResponse{}, ctx.Err()
	case <-timer.C:
		process.protocolFailed = true
		_ = process.stdin.Close()
		return ChildResponse{}, context.DeadlineExceeded
	}
}

func scanPeerChildResponses(
	stdout io.ReadCloser,
	results chan<- childReadResult,
) {
	defer close(results)
	defer stdout.Close()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), MaxChildControlFrame)
	for scanner.Scan() {
		results <- childReadResult{
			data: append([]byte(nil), scanner.Bytes()...),
		}
	}
	if err := scanner.Err(); err != nil {
		select {
		case results <- childReadResult{err: err}:
		default:
		}
	}
}

func (process *PeerChildProcess) killUnboundStartedChild() error {
	if process == nil ||
		process.command == nil ||
		process.command.Process == nil {
		return ErrSupervisorRecovery
	}
	if err := process.command.Process.Kill(); err != nil &&
		!errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-process.done:
		return nil
	case <-time.After(2 * time.Second):
		return ErrSupervisorRecovery
	}
}

func (process *PeerChildProcess) terminateBoundChild() error {
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.command == nil ||
		process.command.Process == nil ||
		revalidateChildIdentity(process.identity) != nil {
		return ErrSupervisorRecovery
	}
	_ = process.command.Process.Signal(syscall.SIGTERM)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-process.done:
		return nil
	case <-timer.C:
	}
	if revalidateChildIdentity(process.identity) != nil {
		return ErrSupervisorRecovery
	}
	if err := process.command.Process.Kill(); err != nil &&
		!errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-process.done:
		return nil
	case <-time.After(2 * time.Second):
		return ErrSupervisorRecovery
	}
}

func encodeChildBootstrap(config PeerConfig) ([]byte, error) {
	value := ChildBootstrap{
		SchemaVersion:                SchemaVersion,
		RunID:                        config.RunID,
		IssuedAt:                     config.Now.Unix(),
		ExpiresAt:                    config.ExpiresAt.Unix(),
		ClientPlatformUUID:           config.Client.ClientPlatformUUID,
		ClientIPv4:                   config.Client.ClientIPv4.String(),
		ClientMAC:                    config.Client.ClientMAC,
		ClientWireGuardPublicKey:     base64.StdEncoding.EncodeToString(config.Client.WireGuardPublicKey),
		ClientDescriptorBase64:       base64.StdEncoding.EncodeToString(config.ClientArtifacts.Descriptor),
		ClientCSRDERBase64:           base64.StdEncoding.EncodeToString(config.ClientArtifacts.TLSClientCSRDER),
		ClientOverlayPublicKeyBase64: base64.StdEncoding.EncodeToString(config.ClientArtifacts.OverlayClientPublicKey),
		PeerPlatformUUID:             config.PeerPlatformUUID,
		PeerIPv4:                     config.PeerIPv4.String(),
		PeerMAC:                      config.PeerMAC,
		SystemSSHHostPublicKeyBase64: base64.StdEncoding.EncodeToString(config.SystemSSHHostPublicKey),
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxChildControlFrame {
		return nil, ErrSupervisorState
	}
	return append(encoded, '\n'), nil
}

func decodePeerChildReady(
	response ChildResponse,
	config PeerConfig,
	clientDescriptor ClientPublicDescriptor,
) (PeerChildReady, error) {
	if response.State != "ready" ||
		response.ErrorCode != "" ||
		response.ActiveTransport != "" ||
		response.QUICBlocked ||
		response.WSSRefused ||
		response.DroppedQUIC != 0 {
		return PeerChildReady{}, ErrSupervisorState
	}
	descriptor, err := decodeBoundedBase64(response.PeerDescriptorBase64)
	if err != nil {
		return PeerChildReady{}, err
	}
	caDER, err := decodeBoundedBase64(response.CADERBase64)
	if err != nil {
		clear(descriptor)
		return PeerChildReady{}, err
	}
	serverDER, err := decodeBoundedBase64(response.ServerCertificateDERBase64)
	if err != nil {
		clear(descriptor)
		clear(caDER)
		return PeerChildReady{}, err
	}
	clientDER, err := decodeBoundedBase64(response.ClientCertificateDERBase64)
	if err != nil {
		clear(descriptor)
		clear(caDER)
		clear(serverDER)
		return PeerChildReady{}, err
	}
	overlayServer, err := decodeBoundedBase64(response.OverlayServerPublicKeyBase64)
	if err != nil {
		clear(descriptor)
		clear(caDER)
		clear(serverDER)
		clear(clientDER)
		return PeerChildReady{}, err
	}
	systemHost, err := decodeBoundedBase64(response.SystemSSHHostPublicKeyBase64)
	if err != nil {
		clear(descriptor)
		clear(caDER)
		clear(serverDER)
		clear(clientDER)
		clear(overlayServer)
		return PeerChildReady{}, err
	}
	manifest, err := decodeBoundedBase64(response.TransferManifestBase64)
	if err != nil {
		clear(descriptor)
		clear(caDER)
		clear(serverDER)
		clear(clientDER)
		clear(overlayServer)
		clear(systemHost)
		return PeerChildReady{}, err
	}
	runNonce, err := decodeBoundedBase64(response.RunNonceBase64)
	if err != nil || len(runNonce) != 32 {
		clear(descriptor)
		clear(caDER)
		clear(serverDER)
		clear(clientDER)
		clear(overlayServer)
		clear(systemHost)
		clear(manifest)
		clear(runNonce)
		return PeerChildReady{}, ErrSupervisorState
	}
	artifacts := PeerPublicArtifacts{
		Descriptor:             descriptor,
		CADER:                  caDER,
		ServerCertificateDER:   serverDER,
		ClientCertificateDER:   clientDER,
		OverlayServerPublicKey: overlayServer,
		SystemSSHHostPublicKey: systemHost,
		TransferManifest:       manifest,
	}
	value, err := DecodePeerPublicDescriptor(
		descriptor,
		artifacts,
		PeerExpectation{
			RunID:                    config.RunID,
			Now:                      config.Now,
			ClientPlatformUUID:       config.Client.ClientPlatformUUID,
			PeerPlatformUUID:         config.PeerPlatformUUID,
			ClientIPv4:               config.Client.ClientIPv4,
			PeerIPv4:                 config.PeerIPv4,
			ClientMAC:                config.Client.ClientMAC,
			PeerMAC:                  config.PeerMAC,
			ClientWireGuardPublicKey: config.Client.WireGuardPublicKey,
			ClientCSRDER:             config.ClientArtifacts.TLSClientCSRDER,
			OverlayClientPublicKey:   config.ClientArtifacts.OverlayClientPublicKey,
		},
	)
	if err != nil ||
		value.RunID != clientDescriptor.RunID ||
		value.RunNonceSHA256 != HashHex(runNonce) {
		clearPeerArtifacts(&artifacts)
		clear(runNonce)
		return PeerChildReady{}, ErrSupervisorState
	}
	return PeerChildReady{
		Descriptor: value,
		Artifacts:  artifacts,
		RunNonce:   runNonce,
	}, nil
}

func bindStartedChildIdentity(
	pid int,
	runID string,
	expectedUID uint32,
) (ChildIdentity, error) {
	info, err := os.Lstat(PeerChildPath)
	if err != nil {
		return ChildIdentity{}, ErrSupervisorState
	}
	hash, err := hashRegularFile(PeerChildPath)
	if err != nil {
		return ChildIdentity{}, err
	}
	pathOutput, err := fixedReadOnlyCommand(
		context.Background(),
		"/bin/ps",
		"-p",
		strconv.Itoa(pid),
		"-o",
		"comm=",
	)
	if err != nil ||
		strings.TrimSpace(string(pathOutput)) != PeerChildPath {
		clear(pathOutput)
		return ChildIdentity{}, ErrSupervisorState
	}
	clear(pathOutput)
	start, liveUID, err := processStartIdentityAndUID(pid)
	if err != nil || liveUID != expectedUID {
		return ChildIdentity{}, ErrSupervisorState
	}
	sessionID, err := unix.Getsid(pid)
	if err != nil || sessionID != pid {
		return ChildIdentity{}, ErrSupervisorState
	}
	return childIdentityFromFile(
		pid,
		start,
		PeerChildPath,
		info,
		hash,
		expectedUID,
		sessionID,
		runID,
	)
}

func revalidateChildIdentity(expected ChildIdentity) error {
	if expected.Validate(expected.RunID) != nil {
		return ErrSupervisorRecovery
	}
	current, err := bindStartedChildIdentity(
		expected.PID,
		expected.RunID,
		expected.UID,
	)
	if err != nil || current != expected {
		return ErrSupervisorRecovery
	}
	return nil
}
