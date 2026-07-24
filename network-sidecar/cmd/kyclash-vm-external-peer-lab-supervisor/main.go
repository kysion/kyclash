//go:build darwin && kyclash_utun && kyclash_vm_external_peer_lab

// kyclash-vm-external-peer-lab-supervisor is the fixed root transaction
// owner for the client role of the reviewed two-VirtualMac lab. It exposes one
// console-owned App socket and one inherited, anonymous, typed child control
// channel. It accepts no caller-selected path, route, endpoint, process,
// command, profile, or environment authority.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
	"golang.org/x/sys/unix"
)

const (
	xucredVersion        = 0
	auditTokenValueCount = 8
	auditEUIDIndex       = 1
	auditRUIDIndex       = 3
	auditPIDIndex        = 5
	auditPIDVersionIndex = 7
	procInfoCallPIDInfo  = 2
	procPIDPathInfo      = 11
	procPIDPathMaximum   = 16 * 1024
	processZombieState   = 5
	anyFileGID           = ^uint32(0)
)

type fileIdentity struct {
	Device           uint64
	Inode            uint64
	Size             uint64
	UID              uint32
	GID              uint32
	Mode             os.FileMode
	Links            uint64
	ModifiedUnixNano int64
}

type socketIdentity struct {
	Device uint64
	Inode  uint64
	UID    uint32
	GID    uint32
}

type processIdentity struct {
	PID        int
	StartSec   int64
	StartUsec  int32
	Path       string
	Effective  uint32
	Real       uint32
	PIDVersion uint32
}

type appIdentity struct {
	Process processIdentity
	Binary  fileIdentity
}

type executableIdentity struct {
	Path   string
	File   fileIdentity
	SHA256 string
}

type auditToken struct {
	Value [auditTokenValueCount]uint32
}

type socketPeerFacts struct {
	UID        uint32
	PID        int
	AuditEUID  uint32
	AuditRUID  uint32
	PIDVersion uint32
}

type childSession struct {
	command    *exec.Cmd
	process    processIdentity
	executable executableIdentity
	control    net.Conn
}

func statIdentity(info os.FileInfo) (fileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, errors.New("filesystem identity is unavailable")
	}
	size := info.Size()
	if size < 0 {
		return fileIdentity{}, errors.New("negative filesystem object size")
	}
	return fileIdentity{
		Device: uint64(stat.Dev), Inode: stat.Ino, Size: uint64(size),
		UID: stat.Uid, GID: stat.Gid, Mode: info.Mode(), Links: uint64(stat.Nlink),
		ModifiedUnixNano: info.ModTime().UnixNano(),
	}, nil
}

func consoleIdentity() (int, int, error) {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return 0, 0, err
	}
	identity, err := statIdentity(info)
	if err != nil || identity.UID == 0 {
		return 0, 0, errors.New("console is not owned by an interactive user")
	}
	return int(identity.UID), int(identity.GID), nil
}

func requireGuestRuntime(consoleUID int) error {
	model, err := unix.Sysctl("hw.model")
	if err != nil {
		return errors.New("cannot identify VM hardware")
	}
	facts := productionRuntimeFacts(os.Geteuid(), consoleUID, model)
	facts.Runner = os.Getenv("KYCLASH_RUNNER_ENVIRONMENT")
	facts.Confirmation = os.Getenv("KYCLASH_VM_LAB_CONFIRM")
	facts.RuntimeTarget = os.Getenv("KYCLASH_RUNTIME_TARGET")
	return validateRuntimeFacts(facts)
}

func requireDirectory(path string, uid, gid uint32, mode os.FileMode) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("fixed directory path is redirected")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != mode.Perm() {
		return errors.New("fixed directory identity is unsafe")
	}
	identity, err := statIdentity(info)
	if err != nil || identity.UID != uid || identity.GID != gid {
		return errors.New("fixed directory ownership is unsafe")
	}
	return nil
}

func requireStageRoot() error {
	return requireDirectory(vmexternalpeerlab.StageRoot, 0, 0, 0o700)
}

func createOrRequireDirectory(path string, uid, gid uint32, mode os.FileMode) error {
	oldMask := unix.Umask(0o077)
	err := os.Mkdir(path, mode.Perm())
	unix.Umask(oldMask)
	if err == nil {
		if err := os.Chown(path, int(uid), int(gid)); err != nil {
			return err
		}
		if err := os.Chmod(path, mode.Perm()); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	return requireDirectory(path, uid, gid, mode)
}

func requireEmptyDirectory(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("stale external-peer public artifacts are present")
	}
	return nil
}

func ensureStateRoot() error {
	parent, err := filepath.EvalSymlinks(filepath.Dir(vmexternalpeerlab.StateRoot))
	if err != nil || parent != "/private/var/tmp" {
		return errors.New("fixed external-peer state parent is unavailable")
	}
	return createOrRequireDirectory(vmexternalpeerlab.StateRoot, 0, 0, 0o711)
}

func ensureCourierRoots(consoleUID, consoleGID int) error {
	if err := createOrRequireDirectory(vmexternalpeerlab.ClientOutboxRoot, 0, 0, 0o711); err != nil {
		return err
	}
	if err := createOrRequireDirectory(
		vmexternalpeerlab.ClientInboxRoot, uint32(consoleUID), uint32(consoleGID), 0o700,
	); err != nil {
		return err
	}
	return nil
}

func requireEmptyPublicRoots() error {
	if err := requireEmptyDirectory(vmexternalpeerlab.ClientOutboxRoot); err != nil {
		return err
	}
	return requireEmptyDirectory(vmexternalpeerlab.ClientInboxRoot)
}

func openStableRegular(path string, uid, gid uint32, mode os.FileMode) (*os.File, fileIdentity, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, fileIdentity{}, errors.New("fixed file path is redirected")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, fileIdentity{}, errors.New("cannot retain fixed file")
	}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode()&os.ModeSymlink != 0 ||
		opened.Mode().Perm() != mode.Perm() {
		return nil, fileIdentity{}, errors.New("fixed file identity is unsafe")
	}
	identity, err := statIdentity(opened)
	if err != nil || identity.UID != uid ||
		(gid != anyFileGID && identity.GID != gid) ||
		identity.Links != 1 {
		return nil, fileIdentity{}, errors.New("fixed file ownership is unsafe")
	}
	current, err := os.Lstat(path)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	currentIdentity, err := statIdentity(current)
	if err != nil || currentIdentity != identity {
		return nil, fileIdentity{}, errors.New("fixed file changed while opening")
	}
	failed = false
	return file, identity, nil
}

func digestAndValidateExecutable(file *os.File) (string, error) {
	var header [32]byte
	if _, err := file.ReadAt(header[:], 0); err != nil {
		return "", err
	}
	if err := validateThinArm64Executable(header[:]); err != nil {
		return "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func loadAppManifest() (appManifest, fileIdentity, error) {
	file, manifestIdentity, err := openStableRegular(
		vmexternalpeerlab.AppManifestPath, 0, 0, 0o400,
	)
	if err != nil {
		return appManifest{}, fileIdentity{}, err
	}
	defer file.Close()
	if manifestIdentity.Size == 0 || manifestIdentity.Size > maximumAppManifestSize {
		return appManifest{}, fileIdentity{}, errors.New("invalid App manifest size")
	}
	manifest, err := decodeAppManifest(file)
	if err != nil {
		return appManifest{}, fileIdentity{}, err
	}
	current, err := file.Stat()
	if err != nil {
		return appManifest{}, fileIdentity{}, err
	}
	currentIdentity, err := statIdentity(current)
	if err != nil || currentIdentity != manifestIdentity {
		return appManifest{}, fileIdentity{}, errors.New("App manifest changed while reading")
	}

	if err := verifyPinnedAppTree(manifest); err != nil {
		return appManifest{}, fileIdentity{}, err
	}

	executable, executableIdentity, err := openStableRegular(
		manifest.ExecutablePath, manifest.ExecutableUID, anyFileGID, os.FileMode(manifest.ExecutableMode),
	)
	if err != nil {
		return appManifest{}, fileIdentity{}, err
	}
	defer executable.Close()
	if executableIdentity.Device != manifest.ExecutableDevice ||
		executableIdentity.Inode != manifest.ExecutableInode ||
		executableIdentity.Size != manifest.ExecutableSize {
		return appManifest{}, fileIdentity{}, errors.New("App executable identity differs from manifest")
	}
	digest, err := digestAndValidateExecutable(executable)
	if err != nil || digest != manifest.ExecutableSHA256 {
		return appManifest{}, fileIdentity{}, errors.New("App executable digest differs from manifest")
	}
	after, err := executable.Stat()
	if err != nil {
		return appManifest{}, fileIdentity{}, err
	}
	afterIdentity, err := statIdentity(after)
	if err != nil || afterIdentity != executableIdentity {
		return appManifest{}, fileIdentity{}, errors.New("App executable changed while hashing")
	}
	return manifest, executableIdentity, nil
}

func verifyPinnedAppTree(manifest appManifest) error {
	if manifest.Validate() != nil {
		return errors.New("invalid App manifest tree pins")
	}
	treeManifest, treeManifestIdentity, err := openStableRegular(
		vmexternalpeerlab.AppTreeManifestPath,
		0,
		0,
		0o400,
	)
	if err != nil {
		return err
	}
	defer treeManifest.Close()
	if treeManifestIdentity.Size == 0 ||
		treeManifestIdentity.Size >
			vmexternalpeerlab.MaximumCanonicalAppTreeManifestSize {
		return errors.New("invalid canonical App tree manifest size")
	}
	treeManifestBytes, err := io.ReadAll(io.LimitReader(
		treeManifest,
		vmexternalpeerlab.MaximumCanonicalAppTreeManifestSize+1,
	))
	if err != nil ||
		len(treeManifestBytes) == 0 ||
		len(treeManifestBytes) >
			vmexternalpeerlab.MaximumCanonicalAppTreeManifestSize {
		clear(treeManifestBytes)
		return errors.New("invalid canonical App tree manifest bytes")
	}
	defer clear(treeManifestBytes)
	if err := vmexternalpeerlab.VerifyCanonicalAppTree(
		vmexternalpeerlab.AppBundlePath,
		treeManifestBytes,
		manifest.AppTreeManifestSHA256,
		manifest.AppTreeSHA256,
		0,
		0,
	); err != nil {
		return errors.New("App tree differs from canonical manifest")
	}
	treeAfter, err := treeManifest.Stat()
	if err != nil {
		return err
	}
	treeAfterIdentity, err := statIdentity(treeAfter)
	if err != nil || treeAfterIdentity != treeManifestIdentity {
		return errors.New(
			"canonical App tree manifest changed while validating",
		)
	}
	return nil
}

func loadRunTicketExpectation(
	expectedSHA256 string,
) (externalpeer.RunTicketExpectation, error) {
	file, identity, err := openStableRegular(
		externalpeer.PeerRunTicketExpectationPath, 0, 0, 0o600,
	)
	if err != nil {
		return externalpeer.RunTicketExpectation{}, err
	}
	defer file.Close()
	if identity.Size == 0 || identity.Size > externalpeer.MaxDescriptorSize {
		return externalpeer.RunTicketExpectation{},
			errors.New("invalid run-ticket expectation size")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, externalpeer.MaxDescriptorSize+1))
	if err != nil || len(encoded) == 0 || len(encoded) > externalpeer.MaxDescriptorSize {
		return externalpeer.RunTicketExpectation{},
			errors.New("invalid run-ticket expectation bytes")
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	if fmt.Sprintf("%x", digest[:]) != expectedSHA256 {
		return externalpeer.RunTicketExpectation{},
			errors.New("run-ticket expectation digest differs from App manifest")
	}
	expectation, err := externalpeer.DecodeRunTicketExpectation(encoded)
	if err != nil {
		return externalpeer.RunTicketExpectation{},
			errors.New("run-ticket expectation contract is invalid")
	}
	after, err := file.Stat()
	if err != nil {
		return externalpeer.RunTicketExpectation{}, err
	}
	afterIdentity, err := statIdentity(after)
	if err != nil || afterIdentity != identity {
		return externalpeer.RunTicketExpectation{},
			errors.New("run-ticket expectation changed while reading")
	}
	return expectation, nil
}

func verifyPeerConfig(
	expectedSHA256 string,
) (externalpeer.PeerSupervisorConfig, error) {
	file, identity, err := openStableRegular(
		externalpeer.PeerFixedConfigPath, 0, 0, 0o600,
	)
	if err != nil {
		return externalpeer.PeerSupervisorConfig{}, err
	}
	defer file.Close()
	if identity.Size == 0 || identity.Size > externalpeer.MaxDescriptorSize {
		return externalpeer.PeerSupervisorConfig{},
			errors.New("invalid external-peer config size")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, externalpeer.MaxDescriptorSize+1))
	if err != nil || len(encoded) == 0 || len(encoded) > externalpeer.MaxDescriptorSize {
		return externalpeer.PeerSupervisorConfig{},
			errors.New("invalid external-peer config bytes")
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	if fmt.Sprintf("%x", digest[:]) != expectedSHA256 {
		return externalpeer.PeerSupervisorConfig{},
			errors.New("external-peer config digest differs from App manifest")
	}
	config, err := externalpeer.DecodePeerSupervisorConfig(encoded)
	if err != nil {
		return externalpeer.PeerSupervisorConfig{},
			errors.New("external-peer config contract is invalid")
	}
	after, err := file.Stat()
	if err != nil {
		return externalpeer.PeerSupervisorConfig{}, err
	}
	afterIdentity, err := statIdentity(after)
	if err != nil || afterIdentity != identity {
		return externalpeer.PeerSupervisorConfig{},
			errors.New("external-peer config changed while reading")
	}
	return config, nil
}

func loadClientListenerBaseline(
	expectedSHA256 string,
	config externalpeer.PeerSupervisorConfig,
) (externalpeer.ListenerBaseline, error) {
	file, identity, err := openStableRegular(
		clientListenerBaseline, 0, 0, 0o600,
	)
	if err != nil {
		return externalpeer.ListenerBaseline{}, err
	}
	defer file.Close()
	if identity.Size == 0 || identity.Size > externalpeer.MaxChildControlFrame {
		return externalpeer.ListenerBaseline{},
			errors.New("invalid client listener baseline size")
	}
	encoded, err := io.ReadAll(io.LimitReader(
		file,
		externalpeer.MaxChildControlFrame+1,
	))
	if err != nil || len(encoded) == 0 ||
		len(encoded) > externalpeer.MaxChildControlFrame {
		clear(encoded)
		return externalpeer.ListenerBaseline{},
			errors.New("invalid client listener baseline bytes")
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	if fmt.Sprintf("%x", digest[:]) != expectedSHA256 {
		return externalpeer.ListenerBaseline{},
			errors.New("client listener baseline digest differs from App manifest")
	}
	baseline, err := externalpeer.DecodeListenerBaseline(encoded)
	if err != nil || baseline.ValidateForVM(config.Client) != nil {
		return externalpeer.ListenerBaseline{},
			errors.New("client listener baseline contract is invalid")
	}
	after, err := file.Stat()
	if err != nil {
		return externalpeer.ListenerBaseline{}, err
	}
	afterIdentity, err := statIdentity(after)
	if err != nil || afterIdentity != identity {
		return externalpeer.ListenerBaseline{},
			errors.New("client listener baseline changed while reading")
	}
	return baseline, nil
}

func auditClientListenerBaseline(
	ctx context.Context,
	baseline externalpeer.ListenerBaseline,
) error {
	auditContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := externalpeer.AuditListenerBaseline(auditContext, baseline); err != nil {
		return errors.New("client listener inventory differs from pinned baseline")
	}
	return nil
}

func continuousClientListenerAudit(
	ctx context.Context,
	baseline externalpeer.ListenerBaseline,
) <-chan error {
	result := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := auditClientListenerBaseline(ctx, baseline); err != nil {
					select {
					case result <- err:
					case <-ctx.Done():
					}
					return
				}
			}
		}
	}()
	return result
}

func verifyCourierPublicKey(expectedSHA256 string) error {
	file, identity, err := openStableRegular(
		vmexternalpeerlab.CourierPublicKey, 0, 0, 0o400,
	)
	if err != nil {
		return err
	}
	defer file.Close()
	if identity.Size != ed25519.PublicKeySize {
		return errors.New("invalid courier public key size")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, ed25519.PublicKeySize+1))
	if err != nil || len(encoded) != ed25519.PublicKeySize {
		return errors.New("invalid courier public key bytes")
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	if fmt.Sprintf("%x", digest[:]) != expectedSHA256 {
		return errors.New("courier public key digest differs from App manifest")
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	afterIdentity, err := statIdentity(after)
	if err != nil || afterIdentity != identity {
		return errors.New("courier public key changed while reading")
	}
	return nil
}

func requireFixedSelf() (executableIdentity, error) {
	executable, err := os.Executable()
	if err != nil || filepath.Clean(executable) != vmexternalpeerlab.SupervisorPath {
		return executableIdentity{},
			errors.New("supervisor is not running from the fixed root stage")
	}
	return executableAt(vmexternalpeerlab.SupervisorPath, 0o755)
}

func rawAuditToken(descriptor int) (auditToken, error) {
	var token auditToken
	length := uint32(unsafe.Sizeof(token))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(descriptor),
		uintptr(unix.SOL_LOCAL),
		uintptr(unix.LOCAL_PEERTOKEN),
		uintptr(unsafe.Pointer(&token)),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	runtime.KeepAlive(&token)
	if errno != 0 {
		return auditToken{}, errno
	}
	if uintptr(length) != unsafe.Sizeof(token) {
		return auditToken{}, errors.New("invalid audit token size")
	}
	return token, nil
}

func socketPeer(connection *net.UnixConn) (socketPeerFacts, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return socketPeerFacts{}, err
	}
	var credentials *unix.Xucred
	var pid int
	var token auditToken
	var socketErr error
	if err := raw.Control(func(descriptor uintptr) {
		credentials, socketErr = unix.GetsockoptXucred(
			int(descriptor), unix.SOL_LOCAL, unix.LOCAL_PEERCRED,
		)
		if socketErr != nil {
			return
		}
		pid, socketErr = unix.GetsockoptInt(
			int(descriptor), unix.SOL_LOCAL, unix.LOCAL_PEERPID,
		)
		if socketErr != nil {
			return
		}
		token, socketErr = rawAuditToken(int(descriptor))
	}); err != nil {
		return socketPeerFacts{}, err
	}
	if socketErr != nil || credentials == nil ||
		credentials.Version != xucredVersion || pid <= 1 {
		return socketPeerFacts{}, errors.New("cannot authenticate App socket peer")
	}
	if token.Value[auditPIDIndex] != uint32(pid) {
		return socketPeerFacts{}, errors.New("App socket PID and audit token differ")
	}
	return socketPeerFacts{
		UID: credentials.Uid, PID: pid,
		AuditEUID:  token.Value[auditEUIDIndex],
		AuditRUID:  token.Value[auditRUIDIndex],
		PIDVersion: token.Value[auditPIDVersionIndex],
	}, nil
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
	if errno != 0 {
		return "", errno
	}
	if count == 0 || count > uintptr(len(buffer)) {
		return "", errors.New("invalid process path size")
	}
	raw := buffer[:count]
	if index := strings.IndexByte(string(raw), 0); index >= 0 {
		raw = raw[:index]
	}
	if len(raw) == 0 || bytesContainControl(raw) {
		return "", errors.New("invalid process path")
	}
	path := string(raw)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("process path is not absolute")
	}
	return path, nil
}

func bytesContainControl(value []byte) bool {
	for _, character := range value {
		if character == 0 || character == '\r' || character == '\n' {
			return true
		}
	}
	return false
}

func inspectProcess(pid int, pidVersion uint32) (processIdentity, int8, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || info == nil || int(info.Proc.P_pid) != pid {
		return processIdentity{}, 0, errors.New("process identity is unavailable")
	}
	path, err := processPath(pid)
	if err != nil {
		return processIdentity{}, 0, err
	}
	return processIdentity{
		PID: pid, StartSec: info.Proc.P_starttime.Sec,
		StartUsec: info.Proc.P_starttime.Usec, Path: path,
		Effective: info.Eproc.Ucred.Uid, Real: info.Eproc.Pcred.P_ruid,
		PIDVersion: pidVersion,
	}, info.Proc.P_stat, nil
}

func authenticateApp(
	connection *net.UnixConn,
	consoleUID int,
	manifest appManifest,
	binary fileIdentity,
) (appIdentity, error) {
	peer, err := socketPeer(connection)
	if err != nil {
		return appIdentity{}, err
	}
	expectedUID := manifest.ExpectedAuditUID
	if expectedUID != uint32(consoleUID) ||
		peer.UID != expectedUID ||
		peer.AuditEUID != expectedUID ||
		peer.AuditRUID != expectedUID {
		return appIdentity{}, errors.New("App socket audit identity is not the console user")
	}
	process, _, err := inspectProcess(peer.PID, peer.PIDVersion)
	if err != nil ||
		process.Path != manifest.ExecutablePath ||
		process.Effective != expectedUID ||
		process.Real != expectedUID {
		return appIdentity{}, errors.New("App process identity differs from manifest")
	}
	if err := requireUnchangedFile(manifest.ExecutablePath, binary); err != nil {
		return appIdentity{}, err
	}
	return appIdentity{Process: process, Binary: binary}, nil
}

func requireUnchangedFile(path string, expected fileIdentity) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("fixed executable is unavailable")
	}
	identity, err := statIdentity(info)
	if err != nil || identity != expected {
		return errors.New("fixed executable identity changed")
	}
	return nil
}

func revalidateApp(
	connection *net.UnixConn,
	manifest appManifest,
	identity appIdentity,
) error {
	peer, err := socketPeer(connection)
	if err != nil ||
		peer.PID != identity.Process.PID ||
		peer.PIDVersion != identity.Process.PIDVersion ||
		peer.UID != manifest.ExpectedAuditUID ||
		peer.AuditEUID != manifest.ExpectedAuditUID ||
		peer.AuditRUID != manifest.ExpectedAuditUID {
		return errors.New("App socket owner changed")
	}
	process, _, err := inspectProcess(peer.PID, peer.PIDVersion)
	if err != nil || process != identity.Process {
		return errors.New("App process identity changed")
	}
	if err := requireUnchangedFile(
		manifest.ExecutablePath,
		identity.Binary,
	); err != nil {
		return err
	}
	return verifyPinnedAppTree(manifest)
}

func identifySocket(path string, uid, gid uint32) (socketIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return socketIdentity{}, errors.New("external-peer App socket identity is unsafe")
	}
	identity, err := statIdentity(info)
	if err != nil || identity.UID != uid || identity.GID != gid {
		return socketIdentity{}, errors.New("external-peer App socket ownership is unsafe")
	}
	return socketIdentity{
		Device: identity.Device, Inode: identity.Inode,
		UID: identity.UID, GID: identity.GID,
	}, nil
}

func listenForApp(consoleUID, consoleGID int) (*net.UnixListener, socketIdentity, error) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(vmexternalpeerlab.SocketPath))
	if err != nil || parent != "/private/var/run" {
		return nil, socketIdentity{}, errors.New("fixed App socket parent is unavailable")
	}
	if _, err := os.Lstat(vmexternalpeerlab.SocketPath); !errors.Is(err, os.ErrNotExist) {
		return nil, socketIdentity{}, errors.New("external-peer App socket already exists")
	}
	address, err := net.ResolveUnixAddr("unix", vmexternalpeerlab.SocketPath)
	if err != nil {
		return nil, socketIdentity{}, err
	}
	oldMask := unix.Umask(0o077)
	listener, err := net.ListenUnix("unix", address)
	unix.Umask(oldMask)
	if err != nil {
		return nil, socketIdentity{}, err
	}
	failed := true
	defer func() {
		if failed {
			_ = listener.Close()
			_ = os.Remove(vmexternalpeerlab.SocketPath)
		}
	}()
	if err := os.Chown(vmexternalpeerlab.SocketPath, consoleUID, consoleGID); err != nil {
		return nil, socketIdentity{}, err
	}
	if err := os.Chmod(vmexternalpeerlab.SocketPath, 0o600); err != nil {
		return nil, socketIdentity{}, err
	}
	identity, err := identifySocket(
		vmexternalpeerlab.SocketPath, uint32(consoleUID), uint32(consoleGID),
	)
	if err != nil {
		return nil, socketIdentity{}, err
	}
	failed = false
	return listener, identity, nil
}

func removeOwnedSocket(identity socketIdentity) {
	current, err := identifySocket(vmexternalpeerlab.SocketPath, identity.UID, identity.GID)
	if err == nil && current == identity {
		_ = os.Remove(vmexternalpeerlab.SocketPath)
	}
}

func acceptOne(ctx context.Context, listener *net.UnixListener) (*net.UnixConn, error) {
	for {
		if err := listener.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return nil, err
		}
		connection, err := listener.AcceptUnix()
		if err == nil {
			return connection, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var netError net.Error
		if errors.As(err, &netError) && netError.Timeout() {
			continue
		}
		return nil, err
	}
}

func executableAt(path string, mode os.FileMode) (executableIdentity, error) {
	file, identity, err := openStableRegular(path, 0, 0, mode)
	if err != nil {
		return executableIdentity{}, err
	}
	defer file.Close()
	digest, err := digestAndValidateExecutable(file)
	if err != nil {
		return executableIdentity{}, err
	}
	after, err := file.Stat()
	if err != nil {
		return executableIdentity{}, err
	}
	afterIdentity, err := statIdentity(after)
	if err != nil || afterIdentity != identity {
		return executableIdentity{}, errors.New("child executable changed while hashing")
	}
	return executableIdentity{Path: path, File: identity, SHA256: digest}, nil
}

func verifyClientExecutablePins(
	expectation externalpeer.RunTicketExpectation,
	manifest appManifest,
	supervisor executableIdentity,
) (executableIdentity, error) {
	if supervisor.Path != vmexternalpeerlab.SupervisorPath ||
		requireUnchangedFile(supervisor.Path, supervisor.File) != nil ||
		matchTicketExecutable(
			expectation,
			"client-supervisor",
			supervisor.File.Size,
			supervisor.SHA256,
		) != nil {
		return executableIdentity{},
			errors.New("client supervisor differs from pinned run ticket")
	}
	harness, err := executableAt(vmexternalpeerlab.HarnessPath, 0o500)
	if err != nil {
		return executableIdentity{}, err
	}
	if err := validateHarnessObservation(
		manifest,
		harness.File.Device,
		harness.File.Inode,
		harness.File.Size,
		harness.SHA256,
	); err != nil {
		return executableIdentity{}, err
	}
	if err := matchTicketExecutable(
		expectation,
		"client-harness",
		harness.File.Size,
		harness.SHA256,
	); err != nil {
		return executableIdentity{}, err
	}
	return harness, nil
}

func anonymousSocketPair() (net.Conn, *os.File, error) {
	descriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	unix.CloseOnExec(descriptors[0])
	unix.CloseOnExec(descriptors[1])
	supervisorFile := os.NewFile(uintptr(descriptors[0]), "supervisor-control")
	childFile := os.NewFile(uintptr(descriptors[1]), "harness-control")
	if supervisorFile == nil || childFile == nil {
		if supervisorFile != nil {
			_ = supervisorFile.Close()
		} else {
			_ = unix.Close(descriptors[0])
		}
		if childFile != nil {
			_ = childFile.Close()
		} else {
			_ = unix.Close(descriptors[1])
		}
		return nil, nil, errors.New("cannot retain anonymous child control")
	}
	connection, err := net.FileConn(supervisorFile)
	_ = supervisorFile.Close()
	if err != nil {
		_ = childFile.Close()
		return nil, nil, err
	}
	return connection, childFile, nil
}

func startHarness(
	connection *net.UnixConn,
	pinned executableIdentity,
) (*childSession, error) {
	executable, err := executableAt(vmexternalpeerlab.HarnessPath, 0o500)
	if err != nil {
		return nil, err
	}
	if executable != pinned {
		return nil, errors.New("harness executable changed after pre-idle admission")
	}
	appFile, err := connection.File()
	if err != nil {
		return nil, err
	}
	defer appFile.Close()
	supervisorControl, childControl, err := anonymousSocketPair()
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = supervisorControl.Close()
		}
	}()
	defer childControl.Close()

	null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer null.Close()
	path, arguments, environment, directory := fixedHarnessInvocation()
	command := &exec.Cmd{
		Path: path, Args: arguments, Env: environment, Dir: directory,
		Stdin: null, Stdout: null, Stderr: null,
		ExtraFiles: []*os.File{appFile, childControl},
	}
	if len(command.ExtraFiles) != 2 || childAppFD != 3 || childSupervisorFD != 4 {
		return nil, errors.New("invalid inherited child descriptor contract")
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	_ = appFile.Close()
	_ = childControl.Close()

	process, _, inspectErr := inspectProcess(command.Process.Pid, 0)
	if inspectErr != nil ||
		process.Path != executable.Path ||
		process.Effective != 0 ||
		process.Real != 0 ||
		requireUnchangedFile(executable.Path, executable.File) != nil {
		_ = supervisorControl.Close()
		// Start returned only after this exact, unreaped child completed exec.
		// It cannot be PID-reused while it remains our unwaited child.
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, errors.New("spawned harness identity is unsafe")
	}
	failed = false
	return &childSession{
		command: command, process: process,
		executable: executable, control: supervisorControl,
	}, nil
}

func childState(session *childSession) (alive bool, err error) {
	info, inspectErr := unix.SysctlKinfoProc("kern.proc.pid", session.process.PID)
	if inspectErr != nil {
		if errors.Is(inspectErr, unix.ESRCH) {
			return false, nil
		}
		return false, inspectErr
	}
	if info == nil || int(info.Proc.P_pid) != session.process.PID {
		return false, errors.New("harness PID identity is unavailable")
	}
	if info.Proc.P_starttime.Sec != session.process.StartSec ||
		info.Proc.P_starttime.Usec != session.process.StartUsec ||
		info.Eproc.Ucred.Uid != 0 || info.Eproc.Pcred.P_ruid != 0 {
		return false, errors.New("harness PID was reused")
	}
	if info.Proc.P_stat == processZombieState {
		return false, nil
	}
	path, err := processPath(session.process.PID)
	if err != nil || path != session.executable.Path {
		return false, errors.New("harness process path changed")
	}
	if err := requireUnchangedFile(session.executable.Path, session.executable.File); err != nil {
		return false, err
	}
	return true, nil
}

func appConnectionOpen(connection *net.UnixConn) (bool, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return false, err
	}
	open := false
	var socketErr error
	if err := raw.Read(func(descriptor uintptr) bool {
		poll := []unix.PollFd{{Fd: int32(descriptor), Events: unix.POLLIN}}
		if _, pollErr := unix.Poll(poll, 0); pollErr != nil {
			socketErr = pollErr
			return true
		}
		if poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			open = false
			return true
		}
		var one [1]byte
		count, _, readErr := unix.Recvfrom(
			int(descriptor), one[:], unix.MSG_PEEK|unix.MSG_DONTWAIT,
		)
		switch {
		case readErr == nil && count > 0:
			open = true
		case readErr == nil && count == 0:
			open = false
		case errors.Is(readErr, unix.EAGAIN) || errors.Is(readErr, unix.EWOULDBLOCK):
			open = true
		default:
			socketErr = readErr
		}
		return true
	}); err != nil {
		return false, err
	}
	return open, socketErr
}

func closeRuntimeUntilSafe(runtimeOwner *vmexternalpeerlab.SupervisorRuntime) error {
	for {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := runtimeOwner.Close(cleanupContext)
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
}

func waitUntilChildStops(session *childSession, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		alive, err := childState(session)
		if err != nil {
			return false, err
		}
		if !alive {
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func terminateAndReap(session *childSession) error {
	if session == nil || session.command == nil || session.command.Process == nil {
		return nil
	}
	_ = session.control.Close()
	stopped, err := waitUntilChildStops(session, 2*time.Second)
	if err != nil {
		return err
	}
	signaled := false
	if !stopped {
		alive, err := childState(session)
		if err != nil {
			return err
		}
		if alive {
			if err := session.command.Process.Signal(syscall.SIGTERM); err != nil &&
				!errors.Is(err, os.ErrProcessDone) {
				return err
			}
			signaled = true
		}
		stopped, err = waitUntilChildStops(session, 3*time.Second)
		if err != nil {
			return err
		}
	}
	if !stopped {
		alive, err := childState(session)
		if err != nil {
			return err
		}
		if alive {
			if err := session.command.Process.Signal(syscall.SIGKILL); err != nil &&
				!errors.Is(err, os.ErrProcessDone) {
				return err
			}
			signaled = true
		}
		stopped, err = waitUntilChildStops(session, 3*time.Second)
		if err != nil {
			return err
		}
	}
	if !stopped {
		return errors.New("exact harness child did not stop")
	}
	waitErr := session.command.Wait()
	var exitError *exec.ExitError
	if signaled && errors.As(waitErr, &exitError) {
		return nil
	}
	return waitErr
}

func supervise(
	ctx context.Context,
	connection *net.UnixConn,
	manifest appManifest,
	app appIdentity,
	session *childSession,
	runtimeOwner *vmexternalpeerlab.SupervisorRuntime,
	listenerBaseline externalpeer.ListenerBaseline,
) error {
	controlContext, cancelControl := context.WithCancel(context.Background())
	defer cancelControl()
	controlResult := make(chan error, 1)
	go func() {
		controlResult <- vmexternalpeerlab.ServeSupervisorControl(
			controlContext, session.control, runtimeOwner,
		)
	}()
	auditContext, cancelAudit := context.WithCancel(ctx)
	defer cancelAudit()
	auditResult := continuousClientListenerAudit(auditContext, listenerBaseline)

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var reason error
	for reason == nil {
		select {
		case <-ctx.Done():
			reason = ctx.Err()
		case err := <-controlResult:
			if err != nil {
				reason = err
			} else {
				reason = io.EOF
			}
		case err := <-auditResult:
			if err != nil {
				reason = err
			} else {
				reason = externalpeer.ErrListenerAudit
			}
		case <-ticker.C:
			if err := revalidateApp(connection, manifest, app); err != nil {
				reason = err
				break
			}
			open, err := appConnectionOpen(connection)
			if err != nil {
				reason = err
				break
			}
			if !open {
				reason = io.EOF
				break
			}
			if alive, err := childState(session); err != nil {
				reason = err
			} else if !alive {
				reason = io.EOF
			}
		}
	}

	cancelAudit()
	// This is deliberately route-first. If positive route absence cannot be
	// established, Close retries while the exact child remains unreaped and
	// PID reuse is impossible.
	if err := closeRuntimeUntilSafe(runtimeOwner); err != nil {
		return err
	}
	cancelControl()
	_ = session.control.Close()
	_ = connection.Close()
	if err := terminateAndReap(session); err != nil {
		return err
	}
	if errors.Is(reason, context.Canceled) ||
		errors.Is(reason, io.EOF) ||
		errors.Is(reason, net.ErrClosed) {
		return nil
	}
	return reason
}

func run(arguments []string) error {
	if err := validateArguments(arguments); err != nil {
		return err
	}
	consoleUID, consoleGID, err := consoleIdentity()
	if err != nil {
		return err
	}
	if err := requireGuestRuntime(consoleUID); err != nil {
		return err
	}
	if err := requireStageRoot(); err != nil {
		return err
	}
	supervisorExecutable, err := requireFixedSelf()
	if err != nil {
		return err
	}
	if err := ensureStateRoot(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Recovery must precede App-manifest and public-artifact admission. A
	// missing candidate or stale courier file must never prevent convergence
	// of a retained privileged route/Mihomo journal.
	runtimeOwner, err := vmexternalpeerlab.NewSupervisorRuntime(ctx)
	if err != nil {
		return err
	}
	runtimeReleased := false
	defer func() {
		if !runtimeReleased {
			_ = closeRuntimeUntilSafe(runtimeOwner)
		}
	}()
	// The console-owned courier directory is deliberately admitted only
	// after privileged journal recovery. A same-UID chmod or stale artifact
	// can refuse a new App, but cannot block route/Mihomo convergence.
	if err := ensureCourierRoots(consoleUID, consoleGID); err != nil {
		return err
	}
	if err := requireEmptyPublicRoots(); err != nil {
		return err
	}
	manifest, binary, err := loadAppManifest()
	if err != nil {
		return err
	}
	if manifest.ExpectedAuditUID != uint32(consoleUID) {
		return errors.New("App manifest does not identify the console user")
	}
	ticketExpectation, err := loadRunTicketExpectation(
		manifest.RunTicketExpectationSHA256,
	)
	if err != nil {
		return err
	}
	harnessExecutable, err := verifyClientExecutablePins(
		ticketExpectation,
		manifest,
		supervisorExecutable,
	)
	if err != nil {
		return err
	}
	fixedConfig, err := verifyPeerConfig(manifest.PeerConfigSHA256)
	if err != nil {
		return err
	}
	if err := verifyCourierPublicKey(manifest.CourierPublicKeySHA256); err != nil {
		return err
	}
	listenerBaseline, err := loadClientListenerBaseline(
		manifest.ClientListenerBaselineSHA256,
		fixedConfig,
	)
	if err != nil {
		return err
	}
	// This is the pre-idle gate: no App socket or child exists yet, so the
	// root-pinned closed listener set is proved before any new run begins.
	if err := auditClientListenerBaseline(ctx, listenerBaseline); err != nil {
		return err
	}

	listener, socket, err := listenForApp(consoleUID, consoleGID)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer removeOwnedSocket(socket)
	connection, err := acceptOne(ctx, listener)
	if err != nil {
		return err
	}
	_ = listener.Close()
	app, err := authenticateApp(connection, consoleUID, manifest, binary)
	if err != nil {
		_ = connection.Close()
		return err
	}
	session, err := startHarness(connection, harnessExecutable)
	if err != nil {
		_ = connection.Close()
		return err
	}
	if err := supervise(
		ctx,
		connection,
		manifest,
		app,
		session,
		runtimeOwner,
		listenerBaseline,
	); err != nil {
		return err
	}
	runtimeReleased = true
	return nil
}

func execute(arguments []string, stderr io.Writer) int {
	if err := run(arguments); err != nil {
		_, _ = fmt.Fprintln(stderr, "KyClash external-peer client supervisor failed")
		return 1
	}
	return 0
}

func main() {
	os.Exit(execute(os.Args[1:], os.Stderr))
}
