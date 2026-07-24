//go:build darwin && kyclash_utun && kyclash_vm_external_peer_lab

package vmexternalpeerlab

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sys/unix"
)

const (
	appleSSHPath             = "/usr/bin/ssh"
	appleCodeSignPath        = "/usr/bin/codesign"
	fixedSSHProofRoot        = StateRoot + "/ssh-proof-v1"
	fixedSSHIdentityPath     = fixedSSHProofRoot + "/identity.pub"
	fixedSSHKnownHostsPath   = fixedSSHProofRoot + "/known_hosts"
	fixedSSHAgentSocketPath  = fixedSSHProofRoot + "/agent.sock"
	fixedSSHRestrictedUser   = "kyclashlabssh"
	fixedSSHProbeTimeout     = 15 * time.Second
	fixedSSHMaxOutput        = 64
	fixedSSHMaxErrorOutput   = 4 * 1024
	fixedSSHStateRootMode    = 0o711
	fixedSSHProofRootMode    = 0o700
	fixedSSHPublicFileMode   = 0o600
	fixedSSHAgentSocketMode  = 0o600
	fixedSSHExecutableMode   = 0o755
	fixedSSHExecutableMaxLen = 64 * 1024 * 1024
)

var errFixedSSHProof = errors.New("fixed external-peer SSH verification failed")

// FixedSSHRunArtifacts are the complete run-bound inputs accepted by the
// verifier. There is deliberately no endpoint, command, filesystem path,
// executable, environment, interface, or process field in this constructor
// authority surface.
type FixedSSHRunArtifacts struct {
	OverlayClientPrivateKey ed25519.PrivateKey
	OverlayClientPublicKey  []byte
	OverlayServerPublicKey  []byte
	SystemSSHHostPublicKey  []byte
	RunNonceSHA256          string
}

type fixedOverlayProbe func(
	context.Context,
	string,
	ed25519.PrivateKey,
	[]byte,
	string,
	externalpeer.OverlayDialContext,
) error

type fixedOverlayDialFactory func(string) (externalpeer.OverlayDialContext, error)

// FixedSSHVerifier proves the in-process overlay service on every carrier and
// the Apple OpenSSH forced-command service only when requireSystem is true.
// All private material remains in this process and is cleared by Close.
type FixedSSHVerifier struct {
	mu sync.Mutex

	clientPrivate   ed25519.PrivateKey
	clientPublic    []byte
	overlayHost     []byte
	systemHost      []byte
	runNonceSHA256  []byte
	appleSSHSHA256  [sha256.Size]byte
	overlayProbe    fixedOverlayProbe
	dialFactory     fixedOverlayDialFactory
	systemProbe     func(context.Context, string) error
	inspectAppleSSH func(context.Context) (fixedSSHExecutableIdentity, error)
	closed          bool
}

// NewFixedSSHVerifier validates the run-bound Ed25519 artifacts and seals the
// SHA-256 identity of Apple's fixed /usr/bin/ssh. It never accepts a caller
// selected target, command, executable, environment, or disk location.
func NewFixedSSHVerifier(artifacts FixedSSHRunArtifacts) (*FixedSSHVerifier, error) {
	if os.Geteuid() != 0 {
		return nil, errFixedSSHProof
	}
	privateKey, clientPublic, overlayHost, systemHost, nonceHash, err := validateFixedSSHArtifacts(artifacts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixedSSHProbeTimeout)
	defer cancel()
	identity, err := inspectFixedAppleSSH(ctx)
	if err != nil {
		clear(privateKey)
		clear(clientPublic)
		clear(overlayHost)
		clear(systemHost)
		clear(nonceHash)
		return nil, err
	}
	verifier := &FixedSSHVerifier{
		clientPrivate:   privateKey,
		clientPublic:    clientPublic,
		overlayHost:     overlayHost,
		systemHost:      systemHost,
		runNonceSHA256:  nonceHash,
		appleSSHSHA256:  identity.sha256,
		overlayProbe:    externalpeer.ProbeOverlaySSH,
		dialFactory:     fixedOverlayDial,
		inspectAppleSSH: inspectFixedAppleSSH,
	}
	verifier.systemProbe = verifier.probeFixedSystemSSH
	return verifier, nil
}

func validateFixedSSHArtifacts(
	artifacts FixedSSHRunArtifacts,
) (
	ed25519.PrivateKey,
	[]byte,
	[]byte,
	[]byte,
	[]byte,
	error,
) {
	if len(artifacts.OverlayClientPrivateKey) != ed25519.PrivateKeySize {
		return nil, nil, nil, nil, nil, errFixedSSHProof
	}
	clientKey, err := parseCanonicalED25519(artifacts.OverlayClientPublicKey)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	derived, err := ssh.NewPublicKey(artifacts.OverlayClientPrivateKey.Public())
	if err != nil || !bytes.Equal(derived.Marshal(), clientKey.Marshal()) {
		return nil, nil, nil, nil, nil, errFixedSSHProof
	}
	if _, err := parseCanonicalED25519(artifacts.OverlayServerPublicKey); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if _, err := parseCanonicalED25519(artifacts.SystemSSHHostPublicKey); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	nonceHash, err := hex.DecodeString(artifacts.RunNonceSHA256)
	if err != nil ||
		len(nonceHash) != sha256.Size ||
		hex.EncodeToString(nonceHash) != artifacts.RunNonceSHA256 {
		clear(nonceHash)
		return nil, nil, nil, nil, nil, errFixedSSHProof
	}
	return append(ed25519.PrivateKey(nil), artifacts.OverlayClientPrivateKey...),
		append([]byte(nil), artifacts.OverlayClientPublicKey...),
		append([]byte(nil), artifacts.OverlayServerPublicKey...),
		append([]byte(nil), artifacts.SystemSSHHostPublicKey...),
		[]byte(artifacts.RunNonceSHA256),
		nil
}

func parseCanonicalED25519(raw []byte) (ssh.PublicKey, error) {
	key, err := ssh.ParsePublicKey(raw)
	if err != nil ||
		key.Type() != ssh.KeyAlgoED25519 ||
		!bytes.Equal(key.Marshal(), raw) {
		return nil, errFixedSSHProof
	}
	return key, nil
}

// VerifySSH binds both proof paths to the exact real utun owned by the
// backend. QUIC/WSS request only the in-process proof; the final TCP carrier
// additionally requests the system OpenSSH proof.
func (verifier *FixedSSHVerifier) VerifySSH(
	ctx context.Context,
	tunnelInterface string,
	requireSystem bool,
) (SSHVerification, error) {
	if verifier == nil {
		return SSHVerification{}, errFixedSSHProof
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if verifier.closed ||
		!validUTUN(tunnelInterface) ||
		len(verifier.clientPrivate) != ed25519.PrivateKeySize ||
		verifier.overlayProbe == nil ||
		verifier.dialFactory == nil {
		return SSHVerification{}, errFixedSSHProof
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dial, err := verifier.dialFactory(tunnelInterface)
	if err != nil {
		return SSHVerification{}, errFixedSSHProof
	}
	if err := verifier.overlayProbe(
		ctx,
		OverlaySSH,
		verifier.clientPrivate,
		verifier.overlayHost,
		string(verifier.runNonceSHA256),
		dial,
	); err != nil {
		return SSHVerification{}, errFixedSSHProof
	}
	result := SSHVerification{InProcessVerified: true}
	if !requireSystem {
		return result, nil
	}
	if verifier.systemProbe == nil || len(verifier.systemHost) == 0 {
		return SSHVerification{}, errFixedSSHProof
	}
	if err := verifier.systemProbe(ctx, tunnelInterface); err != nil {
		return SSHVerification{}, errFixedSSHProof
	}
	result.SystemVerified = true
	return result, nil
}

// Close clears all retained private and run-bound public artifacts. It is
// idempotent and does not delete any path outside the fixed per-probe root.
func (verifier *FixedSSHVerifier) Close() error {
	if verifier == nil {
		return nil
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if verifier.closed {
		return nil
	}
	clear(verifier.clientPrivate)
	clear(verifier.clientPublic)
	clear(verifier.overlayHost)
	clear(verifier.systemHost)
	clear(verifier.runNonceSHA256)
	clear(verifier.appleSSHSHA256[:])
	verifier.clientPrivate = nil
	verifier.clientPublic = nil
	verifier.overlayHost = nil
	verifier.systemHost = nil
	verifier.runNonceSHA256 = nil
	verifier.overlayProbe = nil
	verifier.dialFactory = nil
	verifier.systemProbe = nil
	verifier.inspectAppleSSH = nil
	verifier.closed = true
	return nil
}

func fixedOverlayDial(tunnelInterface string) (externalpeer.OverlayDialContext, error) {
	if !validUTUN(tunnelInterface) {
		return nil, errFixedSSHProof
	}
	networkInterface, err := net.InterfaceByName(tunnelInterface)
	if err != nil || networkInterface == nil || networkInterface.Index <= 0 {
		return nil, errFixedSSHProof
	}
	interfaceIndex := networkInterface.Index
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != OverlaySSH {
			return nil, errFixedSSHProof
		}
		dialer := net.Dialer{
			LocalAddr: &net.TCPAddr{IP: net.IPv4(10, 88, 0, 1)},
			Control: func(_, _ string, raw syscall.RawConn) error {
				var optionErr error
				if err := raw.Control(func(fd uintptr) {
					optionErr = unix.SetsockoptInt(
						int(fd),
						unix.IPPROTO_IP,
						unix.IP_BOUND_IF,
						interfaceIndex,
					)
				}); err != nil {
					return err
				}
				return optionErr
			},
		}
		return dialer.DialContext(ctx, "tcp4", OverlaySSH)
	}, nil
}

func (verifier *FixedSSHVerifier) probeFixedSystemSSH(
	ctx context.Context,
	tunnelInterface string,
) error {
	if verifier.inspectAppleSSH == nil || !validUTUN(tunnelInterface) {
		return errFixedSSHProof
	}
	probeCtx, cancel := context.WithTimeout(ctx, fixedSSHProbeTimeout)
	defer cancel()
	before, err := verifier.inspectAppleSSH(probeCtx)
	if err != nil || before.sha256 != verifier.appleSSHSHA256 {
		return errFixedSSHProof
	}
	workspace, err := createFixedSSHWorkspace(verifier.clientPublic, verifier.systemHost)
	if err != nil {
		return errFixedSSHProof
	}
	defer workspace.close()

	signer, err := ssh.NewSignerFromKey(verifier.clientPrivate)
	if err != nil {
		return errFixedSSHProof
	}
	oneKey := &singleUseAgent{signer: signer}
	server, err := startBoundAgentServer(workspace.listener, oneKey)
	if err != nil {
		return errFixedSSHProof
	}
	defer func() {
		_ = server.close()
		_ = server.wait()
	}()

	arguments := fixedSystemSSHArguments(tunnelInterface)
	command := exec.CommandContext(probeCtx, appleSSHPath, arguments...)
	command.Dir = "/"
	command.Env = []string{
		"HOME=/var/empty",
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin",
		"SSH_AUTH_SOCK=" + fixedSSHAgentSocketPath,
	}
	var stdout boundedCapture
	stdout.limit = fixedSSHMaxOutput
	var stderr boundedCapture
	stderr.limit = fixedSSHMaxErrorOutput
	defer stdout.clear()
	defer stderr.clear()
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil || command.Process == nil {
		return errFixedSSHProof
	}
	if err := server.authorizePID(command.Process.Pid); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return errFixedSSHProof
	}
	waitErr := command.Wait()
	closeErr := server.close()
	agentErr := server.wait()
	if waitErr != nil ||
		closeErr != nil ||
		agentErr != nil ||
		stdout.overflow ||
		len(stdout.data) != 32 ||
		externalpeer.HashHex(stdout.data) != string(verifier.runNonceSHA256) ||
		oneKey.signatureCount() != 1 {
		return errFixedSSHProof
	}
	after, err := verifier.inspectAppleSSH(probeCtx)
	if err != nil || after != before || after.sha256 != verifier.appleSSHSHA256 {
		return errFixedSSHProof
	}
	if err := workspace.close(); err != nil {
		return errFixedSSHProof
	}
	return nil
}

func fixedSystemSSHArguments(tunnelInterface string) []string {
	return []string{
		"-4",
		"-F",
		"/dev/null",
		"-o",
		"BatchMode=yes",
		"-o",
		"PasswordAuthentication=no",
		"-o",
		"KbdInteractiveAuthentication=no",
		"-o",
		"ChallengeResponseAuthentication=no",
		"-o",
		"PreferredAuthentications=publickey",
		"-o",
		"PubkeyAuthentication=yes",
		"-o",
		"IdentitiesOnly=yes",
		"-o",
		"IdentityAgent=" + fixedSSHAgentSocketPath,
		"-o",
		"IdentityFile=" + fixedSSHIdentityPath,
		"-o",
		"UserKnownHostsFile=" + fixedSSHKnownHostsPath,
		"-o",
		"GlobalKnownHostsFile=/dev/null",
		"-o",
		"StrictHostKeyChecking=yes",
		"-o",
		"HostKeyAlgorithms=ssh-ed25519",
		"-o",
		"PubkeyAcceptedAlgorithms=ssh-ed25519",
		"-o",
		"DisableForwarding=yes",
		"-o",
		"ClearAllForwardings=yes",
		"-o",
		"ForwardAgent=no",
		"-o",
		"ForwardX11=no",
		"-o",
		"Tunnel=no",
		"-o",
		"PermitLocalCommand=no",
		"-o",
		"ControlMaster=no",
		"-o",
		"ControlPath=none",
		"-o",
		"ControlPersist=no",
		"-o",
		"ProxyCommand=none",
		"-o",
		"ProxyJump=none",
		"-o",
		"RequestTTY=no",
		"-o",
		"ConnectionAttempts=1",
		"-o",
		"ConnectTimeout=10",
		"-o",
		"NumberOfPasswordPrompts=0",
		"-o",
		"LogLevel=ERROR",
		"-B",
		tunnelInterface,
		"-b",
		"10.88.0.1",
		"-p",
		"2222",
		"-l",
		fixedSSHRestrictedUser,
		"-T",
		"10.88.0.2",
		externalpeer.ForcedCommandName,
	}
}

type fixedSSHWorkspace struct {
	listener *net.UnixListener
	paths    []string
	root     string
}

func createFixedSSHWorkspace(
	clientPublicArtifact []byte,
	systemHostPublicArtifact []byte,
) (*fixedSSHWorkspace, error) {
	return createFixedSSHWorkspaceAt(
		StateRoot,
		fixedSSHProofRoot,
		0,
		fixedSSHStateRootMode,
		clientPublicArtifact,
		systemHostPublicArtifact,
	)
}

func createFixedSSHWorkspaceAt(
	stateRoot string,
	proofRoot string,
	requiredUID uint32,
	requiredStateMode uint16,
	clientPublicArtifact []byte,
	systemHostPublicArtifact []byte,
) (*fixedSSHWorkspace, error) {
	if err := validateFixedDirectory(stateRoot, requiredUID, requiredStateMode); err != nil {
		return nil, err
	}
	clientKey, err := parseCanonicalED25519(clientPublicArtifact)
	if err != nil {
		return nil, err
	}
	systemKey, err := parseCanonicalED25519(systemHostPublicArtifact)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(proofRoot, fixedSSHProofRootMode); err != nil {
		return nil, errFixedSSHProof
	}
	workspace := &fixedSSHWorkspace{
		root: proofRoot,
		paths: []string{
			proofRoot + "/identity.pub",
			proofRoot + "/known_hosts",
			proofRoot + "/agent.sock",
		},
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = workspace.close()
		}
	}()
	if err := validateFixedDirectory(proofRoot, requiredUID, fixedSSHProofRootMode); err != nil {
		return nil, err
	}
	identity := ssh.MarshalAuthorizedKey(clientKey)
	if err := writeExclusivePublicFile(workspace.paths[0], requiredUID, identity); err != nil {
		clear(identity)
		return nil, err
	}
	clear(identity)
	knownHosts := []byte(knownhosts.Line([]string{"[10.88.0.2]:2222"}, systemKey) + "\n")
	if err := writeExclusivePublicFile(workspace.paths[1], requiredUID, knownHosts); err != nil {
		clear(knownHosts)
		return nil, err
	}
	clear(knownHosts)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: workspace.paths[2], Net: "unix"})
	if err != nil {
		return nil, errFixedSSHProof
	}
	listener.SetUnlinkOnClose(true)
	workspace.listener = listener
	if err := os.Chmod(workspace.paths[2], fixedSSHAgentSocketMode); err != nil {
		return nil, errFixedSSHProof
	}
	if err := validateFixedSocket(workspace.paths[2], requiredUID, fixedSSHAgentSocketMode); err != nil {
		return nil, err
	}
	cleanup = false
	return workspace, nil
}

func (workspace *fixedSSHWorkspace) close() error {
	if workspace == nil {
		return nil
	}
	var result error
	if workspace.listener != nil {
		if err := workspace.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
		workspace.listener = nil
	}
	for index := len(workspace.paths) - 1; index >= 0; index-- {
		if err := os.Remove(workspace.paths[index]); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	if workspace.root != "" {
		if err := os.Remove(workspace.root); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	workspace.paths = nil
	workspace.root = ""
	if result != nil {
		return errFixedSSHProof
	}
	return nil
}

func validateFixedDirectory(path string, requiredUID uint32, requiredMode uint16) error {
	var info unix.Stat_t
	if unix.Lstat(path, &info) != nil ||
		info.Mode&unix.S_IFMT != unix.S_IFDIR ||
		info.Uid != requiredUID ||
		info.Mode&0o7777 != requiredMode {
		return errFixedSSHProof
	}
	return nil
}

func validateFixedSocket(path string, requiredUID uint32, requiredMode uint16) error {
	var info unix.Stat_t
	if unix.Lstat(path, &info) != nil ||
		info.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		info.Uid != requiredUID ||
		info.Mode&0o7777 != requiredMode {
		return errFixedSSHProof
	}
	return nil
}

func writeExclusivePublicFile(path string, requiredUID uint32, data []byte) error {
	fd, err := unix.Open(
		path,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		fixedSSHPublicFileMode,
	)
	if err != nil {
		return errFixedSSHProof
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return errFixedSSHProof
	}
	writeErr := error(nil)
	if _, err := file.Write(data); err != nil {
		writeErr = err
	} else if err := file.Sync(); err != nil {
		writeErr = err
	}
	closeErr := file.Close()
	var info unix.Stat_t
	statErr := unix.Lstat(path, &info)
	if writeErr != nil ||
		closeErr != nil ||
		statErr != nil ||
		info.Mode&unix.S_IFMT != unix.S_IFREG ||
		info.Uid != requiredUID ||
		info.Nlink != 1 ||
		info.Mode&0o7777 != fixedSSHPublicFileMode {
		return errFixedSSHProof
	}
	return nil
}

type singleUseAgent struct {
	mu         sync.Mutex
	signer     ssh.Signer
	signatures uint32
}

func (one *singleUseAgent) List() ([]*agent.Key, error) {
	one.mu.Lock()
	defer one.mu.Unlock()
	if one.signer == nil {
		return nil, errFixedSSHProof
	}
	public := one.signer.PublicKey()
	return []*agent.Key{{
		Format:  public.Type(),
		Blob:    append([]byte(nil), public.Marshal()...),
		Comment: "kyclash-external-peer-run-key",
	}}, nil
}

func (one *singleUseAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	one.mu.Lock()
	defer one.mu.Unlock()
	if one.signer == nil ||
		key == nil ||
		!bytes.Equal(key.Marshal(), one.signer.PublicKey().Marshal()) ||
		one.signatures != 0 {
		return nil, errFixedSSHProof
	}
	one.signatures = 1
	signature, err := one.signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, errFixedSSHProof
	}
	return signature, nil
}

func (one *singleUseAgent) Add(agent.AddedKey) error       { return errFixedSSHProof }
func (one *singleUseAgent) Remove(ssh.PublicKey) error     { return errFixedSSHProof }
func (one *singleUseAgent) RemoveAll() error               { return errFixedSSHProof }
func (one *singleUseAgent) Lock([]byte) error              { return errFixedSSHProof }
func (one *singleUseAgent) Unlock([]byte) error            { return errFixedSSHProof }
func (one *singleUseAgent) Signers() ([]ssh.Signer, error) { return nil, errFixedSSHProof }

func (one *singleUseAgent) signatureCount() uint32 {
	one.mu.Lock()
	defer one.mu.Unlock()
	return one.signatures
}

type boundAgentServer struct {
	mu          sync.Mutex
	listener    *net.UnixListener
	oneKey      *singleUseAgent
	ready       chan struct{}
	result      chan error
	expectedPID int
	readyClosed bool
	closed      bool
	waited      bool
}

func startBoundAgentServer(
	listener *net.UnixListener,
	oneKey *singleUseAgent,
) (*boundAgentServer, error) {
	if listener == nil || oneKey == nil {
		return nil, errFixedSSHProof
	}
	server := &boundAgentServer{
		listener: listener,
		oneKey:   oneKey,
		ready:    make(chan struct{}),
		result:   make(chan error, 1),
	}
	go server.serve()
	return server, nil
}

func (server *boundAgentServer) serve() {
	connection, err := server.listener.AcceptUnix()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			server.result <- nil
		} else {
			server.result <- errFixedSSHProof
		}
		return
	}
	defer connection.Close()
	<-server.ready
	server.mu.Lock()
	expectedPID := server.expectedPID
	server.mu.Unlock()
	peerPID, err := localPeerPID(connection)
	if err != nil || expectedPID <= 1 || peerPID != expectedPID {
		server.result <- errFixedSSHProof
		return
	}
	err = agent.ServeAgent(server.oneKey, connection)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		server.result <- errFixedSSHProof
		return
	}
	server.result <- nil
}

func (server *boundAgentServer) authorizePID(pid int) error {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed || server.readyClosed || pid <= 1 {
		return errFixedSSHProof
	}
	server.expectedPID = pid
	server.readyClosed = true
	close(server.ready)
	return nil
}

func (server *boundAgentServer) close() error {
	server.mu.Lock()
	if server.closed {
		server.mu.Unlock()
		return nil
	}
	server.closed = true
	if !server.readyClosed {
		server.readyClosed = true
		close(server.ready)
	}
	listener := server.listener
	server.mu.Unlock()
	if listener == nil {
		return nil
	}
	if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return errFixedSSHProof
	}
	return nil
}

func (server *boundAgentServer) wait() error {
	server.mu.Lock()
	if server.waited {
		server.mu.Unlock()
		return nil
	}
	server.waited = true
	server.mu.Unlock()
	return <-server.result
}

func localPeerPID(connection *net.UnixConn) (int, error) {
	if connection == nil {
		return 0, errFixedSSHProof
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, errFixedSSHProof
	}
	peerPID := 0
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		peerPID, optionErr = unix.GetsockoptInt(
			int(fd),
			unix.SOL_LOCAL,
			unix.LOCAL_PEERPID,
		)
	}); err != nil || optionErr != nil || peerPID <= 1 {
		return 0, errFixedSSHProof
	}
	return peerPID, nil
}

type boundedCapture struct {
	data     []byte
	limit    int
	overflow bool
}

func (capture *boundedCapture) Write(data []byte) (int, error) {
	if capture.limit <= 0 || len(data) > capture.limit-len(capture.data) {
		capture.overflow = true
		return 0, errFixedSSHProof
	}
	capture.data = append(capture.data, data...)
	return len(data), nil
}

func (capture *boundedCapture) clear() {
	clear(capture.data)
	capture.data = nil
	capture.overflow = false
}

type fixedSSHFileIdentity struct {
	device          int32
	inode           uint64
	size            int64
	modifiedSeconds int64
	modifiedNanos   int64
	changedSeconds  int64
	changedNanos    int64
}

type fixedSSHExecutableIdentity struct {
	file   fixedSSHFileIdentity
	sha256 [sha256.Size]byte
}

func inspectFixedAppleSSH(ctx context.Context) (fixedSSHExecutableIdentity, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	before, err := readFixedSSHExecutable()
	if err != nil {
		return fixedSSHExecutableIdentity{}, err
	}
	command := exec.CommandContext(
		ctx,
		appleCodeSignPath,
		fixedAppleCodeSignArguments()...,
	)
	command.Dir = "/"
	command.Env = []string{"HOME=/var/empty", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	var output boundedCapture
	output.limit = fixedSSHMaxErrorOutput
	defer output.clear()
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil || output.overflow {
		return fixedSSHExecutableIdentity{}, errFixedSSHProof
	}
	after, err := readFixedSSHExecutable()
	if err != nil || after != before {
		return fixedSSHExecutableIdentity{}, errFixedSSHProof
	}
	return before, nil
}

func fixedAppleCodeSignArguments() []string {
	return []string{
		"-v",
		"--strict",
		"--verbose=4",
		"-R=anchor apple",
		appleSSHPath,
	}
}

func readFixedSSHExecutable() (fixedSSHExecutableIdentity, error) {
	fd, err := unix.Open(appleSSHPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fixedSSHExecutableIdentity{}, errFixedSSHProof
	}
	file := os.NewFile(uintptr(fd), appleSSHPath)
	if file == nil {
		_ = unix.Close(fd)
		return fixedSSHExecutableIdentity{}, errFixedSSHProof
	}
	defer file.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil ||
		before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Uid != 0 ||
		before.Nlink != 1 ||
		before.Mode&0o7777 != fixedSSHExecutableMode ||
		before.Size <= 0 ||
		before.Size > fixedSSHExecutableMaxLen {
		return fixedSSHExecutableIdentity{}, errFixedSSHProof
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.NewSectionReader(file, 0, before.Size)); err != nil {
		return fixedSSHExecutableIdentity{}, errFixedSSHProof
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	if err := requireArm64MachO(file); err != nil {
		clear(digest[:])
		return fixedSSHExecutableIdentity{}, err
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || !sameFixedSSHStat(before, after) {
		clear(digest[:])
		return fixedSSHExecutableIdentity{}, errFixedSSHProof
	}
	return fixedSSHExecutableIdentity{
		file: fixedSSHFileIdentity{
			device:          before.Dev,
			inode:           before.Ino,
			size:            before.Size,
			modifiedSeconds: before.Mtim.Sec,
			modifiedNanos:   before.Mtim.Nsec,
			changedSeconds:  before.Ctim.Sec,
			changedNanos:    before.Ctim.Nsec,
		},
		sha256: digest,
	}, nil
}

func sameFixedSSHStat(left unix.Stat_t, right unix.Stat_t) bool {
	return left.Dev == right.Dev &&
		left.Ino == right.Ino &&
		left.Size == right.Size &&
		left.Uid == right.Uid &&
		left.Mode == right.Mode &&
		left.Nlink == right.Nlink &&
		left.Mtim == right.Mtim &&
		left.Ctim == right.Ctim
}

func requireArm64MachO(file *os.File) error {
	if file == nil {
		return errFixedSSHProof
	}
	fat, err := macho.NewFatFile(file)
	if err == nil {
		defer fat.Close()
		for _, architecture := range fat.Arches {
			if architecture.Cpu == macho.CpuArm64 {
				return nil
			}
		}
		return errFixedSSHProof
	}
	if !errors.Is(err, macho.ErrNotFat) {
		return errFixedSSHProof
	}
	thin, err := macho.NewFile(file)
	if err != nil {
		return errFixedSSHProof
	}
	defer thin.Close()
	if thin.Cpu != macho.CpuArm64 {
		return errFixedSSHProof
	}
	return nil
}
