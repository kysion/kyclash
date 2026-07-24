//go:build darwin && kyclash_utun && kyclash_vm_external_peer_lab

// kyclash-vm-external-peer-lab-harness owns all client-side private material,
// the real utun backend, and the validated external carrier profile. Its only
// inputs are inherited fd 3 (the authenticated App stream), inherited fd 4
// (the anonymous typed root-supervisor channel), and fixed root-pinned public
// configuration. No endpoint, path, route, command, or policy comes from argv,
// environment, the App, or an unsigned public envelope.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/kysion/kyclash/network-sidecar/internal/bootstrap"
	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/ipc"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const (
	xucredVersion       = 0
	procInfoCallPIDInfo = 2
	procPIDPathInfo     = 11
	procPIDPathMaximum  = 16 * 1024
	maximumPinnedFile   = 64 * 1024 * 1024
	maximumIORegOutput  = 64 * 1024
	hostPublicKeyMax    = 4 * 1024
)

var platformUUIDPattern = regexp.MustCompile(
	`(?m)^[ \t]*"IOPlatformUUID"[ \t]*=[ \t]*"([0-9A-Fa-f-]{36})"[ \t]*$`,
)

type stableFileIdentity struct {
	Device           uint64
	Inode            uint64
	Size             uint64
	UID              uint32
	GID              uint32
	Mode             os.FileMode
	Links            uint64
	ModifiedUnixNano int64
}

type localTicketArtifact struct {
	name   string
	path   string
	mode   os.FileMode
	anyGID bool
}

type clientRuntimeIdentity struct {
	Model string
	Facts externalpeer.CourierVMFacts
}

type harnessResources struct {
	bootstrapConfig bootstrap.Config
	clientIdentity  *externalpeer.ClientIdentity
	store           *vmexternalpeerlab.ClientCourierStore
	courierInput    *vmexternalpeerlab.ClientCourierInput
	clientArtifacts *externalpeer.ClientPublicArtifacts
	clientManifest  []byte
	courierKey      ed25519.PublicKey
	wireGuardPublic []byte
	supervisor      *vmexternalpeerlab.ProtocolSupervisorClient
	sshVerifier     *vmexternalpeerlab.FixedSSHVerifier
	backend         *vmexternalpeerlab.Backend
}

func (resources *harnessResources) close() error {
	if resources == nil {
		return nil
	}
	var result error
	if resources.backend != nil {
		for {
			if err := resources.backend.Close(); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		resources.backend = nil
	}
	if resources.supervisor != nil {
		result = errors.Join(result, resources.supervisor.Close())
		resources.supervisor = nil
	}
	if resources.sshVerifier != nil {
		result = errors.Join(result, resources.sshVerifier.Close())
		resources.sshVerifier = nil
	}
	if resources.clientIdentity != nil {
		resources.clientIdentity.Clear()
		resources.clientIdentity = nil
	}
	resources.bootstrapConfig.Clear()
	if resources.courierInput != nil {
		resources.courierInput.Clear()
		resources.courierInput = nil
	}
	if resources.clientArtifacts != nil {
		clear(resources.clientArtifacts.Descriptor)
		clear(resources.clientArtifacts.TLSClientCSRDER)
		clear(resources.clientArtifacts.OverlayClientPublicKey)
		*resources.clientArtifacts = externalpeer.ClientPublicArtifacts{}
		resources.clientArtifacts = nil
	}
	clear(resources.clientManifest)
	clear(resources.courierKey)
	clear(resources.wireGuardPublic)
	resources.clientManifest = nil
	resources.courierKey = nil
	resources.wireGuardPublic = nil
	if resources.store != nil {
		result = errors.Join(result, resources.store.Cleanup())
		result = errors.Join(result, resources.store.Close())
		resources.store = nil
	}
	return result
}

func statIdentity(info os.FileInfo) (stableFileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Size() < 0 {
		return stableFileIdentity{}, errors.New("filesystem identity unavailable")
	}
	return stableFileIdentity{
		Device: uint64(stat.Dev), Inode: stat.Ino, Size: uint64(info.Size()),
		UID: stat.Uid, GID: stat.Gid, Mode: info.Mode(), Links: uint64(stat.Nlink),
		ModifiedUnixNano: info.ModTime().UnixNano(),
	}, nil
}

func readStableRootFile(
	path string,
	mode os.FileMode,
	maximum int,
	anyGID bool,
) ([]byte, stableFileIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum < 1 {
		return nil, stableFileIdentity{}, errors.New("invalid fixed file contract")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, stableFileIdentity{}, errors.New("fixed file path is redirected")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, stableFileIdentity{}, err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, stableFileIdentity{}, errors.New("cannot retain fixed file")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() ||
		before.Mode().Perm() != mode.Perm() {
		return nil, stableFileIdentity{}, errors.New("fixed file identity is unsafe")
	}
	identity, err := statIdentity(before)
	if err != nil || identity.UID != 0 || !anyGID && identity.GID != 0 ||
		identity.Links != 1 || identity.Size == 0 || identity.Size > uint64(maximum) {
		return nil, stableFileIdentity{}, errors.New("fixed file ownership is unsafe")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maximum ||
		uint64(len(encoded)) != identity.Size {
		clear(encoded)
		return nil, stableFileIdentity{}, errors.New("fixed file size changed")
	}
	after, err := file.Stat()
	if err != nil {
		clear(encoded)
		return nil, stableFileIdentity{}, errors.New("fixed file changed while reading")
	}
	afterIdentity, identityErr := statIdentity(after)
	if identityErr != nil || afterIdentity != identity {
		clear(encoded)
		return nil, stableFileIdentity{}, errors.New("fixed file changed while reading")
	}
	return encoded, identity, nil
}

func requireThinArm64Executable(data []byte) error {
	if len(data) < 32 ||
		!bytes.Equal(data[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) ||
		!bytes.Equal(data[4:8], []byte{0x0c, 0x00, 0x00, 0x01}) ||
		!bytes.Equal(data[12:16], []byte{0x02, 0x00, 0x00, 0x00}) {
		return errors.New("fixed executable is not thin arm64 Mach-O")
	}
	return nil
}

func requireFixedSelf() ([]byte, stableFileIdentity, error) {
	path, err := os.Executable()
	if err != nil || path != vmexternalpeerlab.HarnessPath {
		return nil, stableFileIdentity{}, errors.New("harness is not at its fixed root path")
	}
	encoded, identity, err := readStableRootFile(
		vmexternalpeerlab.HarnessPath, 0o500, maximumPinnedFile, false,
	)
	if err != nil {
		return nil, stableFileIdentity{}, err
	}
	if err := requireThinArm64Executable(encoded); err != nil {
		clear(encoded)
		return nil, stableFileIdentity{}, err
	}
	return encoded, identity, nil
}

func requireFixedStageRoot() error {
	resolved, err := filepath.EvalSymlinks(vmexternalpeerlab.StageRoot)
	if err != nil || resolved != vmexternalpeerlab.StageRoot {
		return errors.New("fixed stage root is redirected")
	}
	info, err := os.Lstat(vmexternalpeerlab.StageRoot)
	if err != nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 {
		return errors.New("fixed stage root mode is unsafe")
	}
	identity, err := statIdentity(info)
	if err != nil ||
		identity.UID != 0 ||
		identity.GID != 0 ||
		identity.Links < 1 {
		return errors.New("fixed stage root ownership is unsafe")
	}
	return nil
}

func consoleIdentity() (int, int, error) {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return 0, 0, err
	}
	identity, err := statIdentity(info)
	if err != nil || identity.UID == 0 {
		return 0, 0, errors.New("interactive console user is required")
	}
	return int(identity.UID), int(identity.GID), nil
}

func requireRuntime(consoleUID int) (string, error) {
	model, err := unix.Sysctl("hw.model")
	if err != nil {
		return "", errors.New("cannot identify VirtualMac model")
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if err := validateRuntimeFacts(runtimeFacts{
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		EffectiveUID: os.Geteuid(), ConsoleUID: consoleUID,
		Model: model, WorkingDir: workingDirectory,
		Environment: os.Environ(),
	}); err != nil {
		return "", err
	}
	return strings.TrimSpace(model), nil
}

func inheritedSocket(descriptor int, name string) (*os.File, error) {
	if descriptor != inheritedAppFD && descriptor != inheritedSupervisorFD {
		return nil, errors.New("invalid inherited descriptor")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, errors.New("inherited descriptor is not a socket")
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		return nil, errors.New("cannot retain inherited socket")
	}
	return file, nil
}

func socketPeer(file *os.File) (uint32, int, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var credentials *unix.Xucred
	var pid int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptXucred(
			int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED,
		)
		if socketErr == nil {
			pid, socketErr = unix.GetsockoptInt(
				int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID,
			)
		}
	}); err != nil {
		return 0, 0, err
	}
	if socketErr != nil || credentials == nil ||
		credentials.Version != xucredVersion || pid <= 1 {
		return 0, 0, errors.New("cannot authenticate inherited socket peer")
	}
	return credentials.Uid, pid, nil
}

func processPath(pid int) (string, error) {
	if pid <= 1 {
		return "", errors.New("invalid process PID")
	}
	buffer := make([]byte, procPIDPathMaximum)
	count, _, errno := unix.Syscall6(
		unix.SYS_PROC_INFO,
		procInfoCallPIDInfo,
		uintptr(pid),
		procPIDPathInfo,
		0,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	runtime.KeepAlive(buffer)
	if errno != 0 || count == 0 || count > uintptr(len(buffer)) {
		return "", errors.New("cannot identify inherited socket peer process")
	}
	raw := buffer[:count]
	if index := bytes.IndexByte(raw, 0); index >= 0 {
		raw = raw[:index]
	}
	if len(raw) == 0 || bytes.ContainsAny(raw, "\x00\r\n") {
		return "", errors.New("invalid inherited socket peer path")
	}
	path := string(raw)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("inherited socket peer path is not absolute")
	}
	return path, nil
}

func validateInheritedPeers(appFile, controlFile *os.File, consoleUID int) error {
	appUID, _, err := socketPeer(appFile)
	if err != nil || appUID != uint32(consoleUID) {
		return errors.New("inherited App stream peer is invalid")
	}
	controlUID, controlPID, err := socketPeer(controlFile)
	if err != nil || controlUID != 0 || controlPID != os.Getppid() {
		return errors.New("inherited supervisor peer is invalid")
	}
	path, err := processPath(controlPID)
	if err != nil || path != vmexternalpeerlab.SupervisorPath {
		return errors.New("inherited supervisor process path is invalid")
	}
	return nil
}

func readPinnedConfiguration() (
	externalpeer.PeerSupervisorConfig,
	externalpeer.RunTicketExpectation,
	ed25519.PublicKey,
	[]byte,
	error,
) {
	configBytes, _, err := readStableRootFile(
		externalpeer.PeerFixedConfigPath, 0o600,
		externalpeer.MaxDescriptorSize, false,
	)
	if err != nil {
		return externalpeer.PeerSupervisorConfig{}, externalpeer.RunTicketExpectation{}, nil, nil, err
	}
	defer clear(configBytes)
	config, err := externalpeer.DecodePeerSupervisorConfig(configBytes)
	if err != nil {
		return externalpeer.PeerSupervisorConfig{}, externalpeer.RunTicketExpectation{}, nil, nil, err
	}
	expectationBytes, _, err := readStableRootFile(
		externalpeer.PeerRunTicketExpectationPath, 0o600,
		externalpeer.MaxDescriptorSize, false,
	)
	if err != nil {
		return externalpeer.PeerSupervisorConfig{}, externalpeer.RunTicketExpectation{}, nil, nil, err
	}
	defer clear(expectationBytes)
	expectation, err := externalpeer.DecodeRunTicketExpectation(expectationBytes)
	if err != nil {
		return externalpeer.PeerSupervisorConfig{}, externalpeer.RunTicketExpectation{}, nil, nil, err
	}
	publicKey, _, err := readStableRootFile(
		vmexternalpeerlab.CourierPublicKey, 0o400, ed25519.PublicKeySize, false,
	)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		clear(publicKey)
		return externalpeer.PeerSupervisorConfig{}, externalpeer.RunTicketExpectation{}, nil, nil,
			errors.New("invalid pinned courier public key")
	}
	return config, expectation, ed25519.PublicKey(publicKey), append([]byte(nil), configBytes...), nil
}

func verifyLocalTicketArtifacts(
	expectation externalpeer.RunTicketExpectation,
	selfBytes []byte,
	selfIdentity stableFileIdentity,
	configBytes []byte,
) error {
	local := []localTicketArtifact{
		{name: "app", path: fixedAppExecutable, mode: 0o755, anyGID: true},
		{name: "client-supervisor", path: vmexternalpeerlab.SupervisorPath, mode: 0o755},
	}
	for _, artifact := range local {
		encoded, identity, err := readStableRootFile(
			artifact.path, artifact.mode, maximumPinnedFile, artifact.anyGID,
		)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(encoded)
		clear(encoded)
		if err := matchTicketArtifact(
			expectation, artifact.name, identity.Size, hex.EncodeToString(digest[:]),
		); err != nil {
			return err
		}
	}
	selfDigest := sha256.Sum256(selfBytes)
	if err := matchTicketArtifact(
		expectation, "client-harness", selfIdentity.Size,
		hex.EncodeToString(selfDigest[:]),
	); err != nil {
		return err
	}
	configDigest := sha256.Sum256(configBytes)
	return matchTicketArtifact(
		expectation, "peer-config", uint64(len(configBytes)),
		hex.EncodeToString(configDigest[:]),
	)
}

func platformUUID() (string, error) {
	command := exec.Command(
		"/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice",
	)
	command.Env = []string{}
	command.Dir = "/"
	command.Stdin = nil
	outputPipe, err := command.StdoutPipe()
	if err != nil {
		return "", err
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return "", err
	}
	output, readErr := io.ReadAll(io.LimitReader(outputPipe, maximumIORegOutput+1))
	waitErr := command.Wait()
	if readErr != nil || waitErr != nil || len(output) == 0 ||
		len(output) > maximumIORegOutput {
		clear(output)
		return "", errors.New("cannot read IOPlatformUUID")
	}
	defer clear(output)
	matches := platformUUIDPattern.FindAllSubmatch(output, -1)
	if len(matches) != 1 || len(matches[0]) != 2 {
		return "", errors.New("IOPlatformUUID is ambiguous")
	}
	return string(matches[0][1]), nil
}

func systemSSHHostFingerprint() (string, error) {
	encoded, _, err := readStableRootFile(
		externalpeer.SystemSSHHostPublicKeyPath, 0o644,
		hostPublicKeyMax, false,
	)
	if err != nil {
		return "", err
	}
	defer clear(encoded)
	key, _, options, rest, err := ssh.ParseAuthorizedKey(encoded)
	if err != nil || key == nil || key.Type() != ssh.KeyAlgoED25519 ||
		len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("invalid system SSH host public key")
	}
	return ssh.FingerprintSHA256(key), nil
}

func collectClientRuntimeIdentity(model string) (clientRuntimeIdentity, error) {
	uuid, err := platformUUID()
	if err != nil {
		return clientRuntimeIdentity{}, err
	}
	networkInterface, err := net.InterfaceByName(externalpeer.BindInterface)
	if err != nil || networkInterface == nil ||
		networkInterface.Flags&net.FlagUp == 0 ||
		len(networkInterface.HardwareAddr) != 6 {
		return clientRuntimeIdentity{}, errors.New("fixed client en0 is unavailable")
	}
	addresses, err := networkInterface.Addrs()
	if err != nil {
		return clientRuntimeIdentity{}, err
	}
	var private []netip.Addr
	for _, address := range addresses {
		prefix, parseErr := netip.ParsePrefix(address.String())
		if parseErr != nil {
			continue
		}
		candidate := prefix.Addr().Unmap()
		if candidate.Is4() && candidate.IsPrivate() &&
			!candidate.IsLoopback() && !vmexternalpeerlab.CoveringPrefix().Contains(candidate) {
			private = append(private, candidate)
		}
	}
	if len(private) != 1 {
		return clientRuntimeIdentity{}, errors.New("client en0 private IPv4 is ambiguous")
	}
	hostFingerprint, err := systemSSHHostFingerprint()
	if err != nil {
		return clientRuntimeIdentity{}, err
	}
	facts, err := externalpeer.NewCourierVMFacts(
		"client",
		externalpeer.ClientVMName,
		uuid,
		hostFingerprint,
		networkInterface.HardwareAddr.String(),
		private[0],
	)
	if err != nil {
		return clientRuntimeIdentity{}, err
	}
	return clientRuntimeIdentity{Model: model, Facts: facts}, nil
}

func generateRunID() (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	runID, err := runIDFromEntropy(entropy[:])
	clear(entropy[:])
	return runID, err
}

func startEOFMonitor(
	ctx context.Context,
	cancel context.CancelFunc,
	appFile *os.File,
	controlFile *os.File,
) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				poll := []unix.PollFd{
					{Fd: int32(appFile.Fd()), Events: unix.POLLIN},
					{Fd: int32(controlFile.Fd()), Events: unix.POLLIN},
				}
				if _, err := unix.Poll(poll, 0); err != nil {
					cancel()
					return
				}
				for _, descriptor := range poll {
					if descriptor.Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
						cancel()
						return
					}
				}
			}
		}
	}()
	var once bool
	return func() {
		if !once {
			close(done)
			once = true
		}
	}
}

func runSession(
	ctx context.Context,
	appFile *os.File,
	controlFile *os.File,
	consoleUID, consoleGID int,
	model string,
	selfBytes []byte,
	selfIdentity stableFileIdentity,
) (runErr error) {
	resources := &harnessResources{}
	defer func() {
		runErr = errors.Join(runErr, resources.close())
	}()

	reader := bufio.NewReaderSize(appFile, 64*1024+1)
	config, err := bootstrap.DecodeLine(reader)
	if err != nil {
		return err
	}
	resources.bootstrapConfig = config
	authProof := bootstrap.AuthProof(config)
	clear(resources.bootstrapConfig.AuthToken)
	resources.bootstrapConfig.AuthToken = nil
	wireGuardPublic, err := curve25519.X25519(
		resources.bootstrapConfig.PrivateKey, curve25519.Basepoint,
	)
	if err != nil {
		return err
	}
	resources.wireGuardPublic = wireGuardPublic

	fixedConfig, ticketExpectation, courierKey, configBytes, err := readPinnedConfiguration()
	if err != nil {
		return err
	}
	defer clear(configBytes)
	resources.courierKey = courierKey
	if fixedConfig.ConsoleUID != uint32(consoleUID) ||
		fixedConfig.ConsoleGID != uint32(consoleGID) {
		return errors.New("pinned config console identity differs")
	}
	if err := verifyLocalTicketArtifacts(
		ticketExpectation, selfBytes, selfIdentity, configBytes,
	); err != nil {
		return err
	}
	expectedClientFacts, err := fixedConfig.Client.CourierFacts()
	if err != nil {
		return err
	}
	runtimeIdentity, err := collectClientRuntimeIdentity(model)
	if err != nil {
		return err
	}
	if err := validatePinnedClientFacts(runtimeIdentity.Facts, expectedClientFacts); err != nil {
		return err
	}

	runID, err := generateRunID()
	if err != nil {
		return err
	}
	identity, err := externalpeer.NewClientIdentity(runID)
	if err != nil {
		return err
	}
	resources.clientIdentity = identity
	clientIPv4 := netip.AddrFrom4(runtimeIdentity.Facts.IPv4)
	expiresAt := time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second)
	clientDescriptor, clientArtifacts, err := identity.PublicArtifacts(
		externalpeer.ClientDescriptorConfig{
			RunID: runID, ExpiresAt: expiresAt,
			VirtualMacModel:    runtimeIdentity.Model,
			PlatformUUID:       runtimeIdentity.Facts.PlatformUUID,
			ClientIPv4:         clientIPv4,
			ClientMAC:          net.HardwareAddr(runtimeIdentity.Facts.MAC[:]).String(),
			WireGuardPublicKey: resources.wireGuardPublic,
		},
	)
	if err != nil {
		return err
	}
	resources.clientArtifacts = &clientArtifacts
	if _, err := externalpeer.DecodeClientPublicDescriptor(
		clientArtifacts.Descriptor,
		clientArtifacts,
		externalpeer.ClientExpectation{
			RunID: runID, Now: time.Now().UTC(),
			ClientPlatformUUID: runtimeIdentity.Facts.PlatformUUID,
			ClientIPv4:         clientIPv4,
			ClientMAC:          net.HardwareAddr(runtimeIdentity.Facts.MAC[:]).String(),
			WireGuardPublicKey: resources.wireGuardPublic,
		},
	); err != nil {
		return err
	}
	if clientDescriptor.RunID != runID {
		return errors.New("client descriptor run identity changed")
	}

	store, err := vmexternalpeerlab.OpenClientCourierStore(uint32(consoleUID))
	if err != nil {
		return err
	}
	resources.store = store
	clientFiles, clientManifest, err := store.PublishClientBundle(runID, clientArtifacts)
	if err != nil {
		return err
	}
	resources.clientManifest = clientManifest
	startupContext, cancelStartup := context.WithTimeout(
		ctx, time.Duration(vmexternalpeerlab.StartupSeconds)*time.Second,
	)
	input, err := store.WaitPeerBundle(startupContext)
	cancelStartup()
	if err != nil {
		return err
	}
	resources.courierInput = &input

	// The underlay identity must still match the root-pinned same-run facts
	// after the courier wait and immediately before any carrier construction.
	reobserved, err := collectClientRuntimeIdentity(model)
	if err != nil || reobserved != runtimeIdentity {
		return errors.New("client VM identity changed during courier exchange")
	}
	now := time.Now().UTC()
	peerFiles, err := vmexternalpeerlab.ValidateCourierExchange(
		runID,
		now,
		resources.courierKey,
		fixedConfig,
		ticketExpectation,
		clientFiles,
		clientManifest,
		input,
	)
	if err != nil || len(peerFiles) != len(externalpeer.PeerArtifactNames) {
		return errors.New("signed external-peer courier exchange failed")
	}
	peerIPv4, err := netip.ParseAddr(fixedConfig.Peer.IPv4)
	if err != nil {
		return err
	}
	peerDescriptor, err := externalpeer.DecodePeerPublicDescriptor(
		input.PeerArtifacts.Descriptor,
		input.PeerArtifacts,
		externalpeer.PeerExpectation{
			RunID: runID, Now: now,
			ClientPlatformUUID: fixedConfig.Client.PlatformUUID,
			PeerPlatformUUID:   fixedConfig.Peer.PlatformUUID,
			ClientIPv4:         clientIPv4, PeerIPv4: peerIPv4,
			ClientMAC: fixedConfig.Client.MAC, PeerMAC: fixedConfig.Peer.MAC,
			ClientWireGuardPublicKey: resources.wireGuardPublic,
			ClientCSRDER:             clientArtifacts.TLSClientCSRDER,
			OverlayClientPublicKey:   clientArtifacts.OverlayClientPublicKey,
		},
	)
	if err != nil ||
		peerDescriptor.SystemSSHHostPublicKeyFingerprint != fixedConfig.Peer.SSHHostFingerprint {
		return errors.New("validated peer descriptor differs from pinned peer identity")
	}
	strictProfile, err := vmexternalpeerlab.ProfileFromValidatedPeerDescriptor(peerDescriptor)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(input.PeerArtifacts.CADER)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	clientTLSCertificate, err := identity.TLSCertificate(
		input.PeerArtifacts.ClientCertificateDER,
	)
	if err != nil {
		return err
	}
	sshVerifier, err := vmexternalpeerlab.NewFixedSSHVerifier(
		vmexternalpeerlab.FixedSSHRunArtifacts{
			OverlayClientPrivateKey: identity.OverlayPrivateKey,
			OverlayClientPublicKey:  clientArtifacts.OverlayClientPublicKey,
			OverlayServerPublicKey:  input.PeerArtifacts.OverlayServerPublicKey,
			SystemSSHHostPublicKey:  input.PeerArtifacts.SystemSSHHostPublicKey,
			RunNonceSHA256:          peerDescriptor.RunNonceSHA256,
		},
	)
	if err != nil {
		return err
	}
	resources.sshVerifier = sshVerifier

	controlConnection, err := net.FileConn(controlFile)
	if err != nil {
		return err
	}
	supervisor, err := vmexternalpeerlab.NewProtocolSupervisorClient(controlConnection)
	if err != nil {
		_ = controlConnection.Close()
		return err
	}
	resources.supervisor = supervisor
	backend, err := vmexternalpeerlab.NewBackend(
		resources.bootstrapConfig.PrivateKey,
		roots,
		clientTLSCertificate,
		strictProfile,
		resources.bootstrapConfig.InstanceID,
		supervisor,
		sshVerifier,
	)
	// NewBackend owns independent copies. The local tls.Certificate shares
	// the identity's key, so erase this second owner immediately.
	clearTLSCertificate(&clientTLSCertificate)
	if err != nil {
		return err
	}
	resources.backend = backend
	clear(resources.bootstrapConfig.PrivateKey)
	resources.bootstrapConfig.PrivateKey = nil
	clear(resources.wireGuardPublic)
	resources.wireGuardPublic = nil

	handshake, err := newRedactedHandshake(
		resources.bootstrapConfig.InstanceID, authProof,
	)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(appFile).Encode(handshake); err != nil {
		return errors.New("write redacted external-peer handshake")
	}
	return ipc.ServeWithPreappliedProfileContext(
		ctx,
		reader,
		appFile,
		appFile,
		backend,
		strictProfile,
	)
}

func run(arguments []string) error {
	if err := validateArguments(arguments); err != nil {
		return err
	}
	consoleUID, consoleGID, err := consoleIdentity()
	if err != nil {
		return err
	}
	model, err := requireRuntime(consoleUID)
	if err != nil {
		return err
	}
	if err := requireFixedStageRoot(); err != nil {
		return err
	}
	selfBytes, selfIdentity, err := requireFixedSelf()
	if err != nil {
		return err
	}
	defer clear(selfBytes)
	appFile, err := inheritedSocket(inheritedAppFD, "authenticated-app-stream")
	if err != nil {
		return err
	}
	defer appFile.Close()
	controlFile, err := inheritedSocket(inheritedSupervisorFD, "anonymous-supervisor-control")
	if err != nil {
		return err
	}
	defer controlFile.Close()
	if err := validateInheritedPeers(appFile, controlFile, consoleUID); err != nil {
		return err
	}
	signalContext, stopSignals := signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGTERM,
	)
	defer stopSignals()
	ownerContext, cancelOwner := context.WithCancel(signalContext)
	defer cancelOwner()
	stopMonitor := startEOFMonitor(ownerContext, cancelOwner, appFile, controlFile)
	defer stopMonitor()
	return runSession(
		ownerContext,
		appFile,
		controlFile,
		consoleUID,
		consoleGID,
		model,
		selfBytes,
		selfIdentity,
	)
}

func execute(arguments []string, stderr io.Writer) int {
	if err := run(arguments); err != nil {
		_, _ = fmt.Fprintln(stderr, "KyClash external-peer client harness failed")
		return 1
	}
	return 0
}

func main() {
	os.Exit(execute(os.Args[1:], os.Stderr))
}
