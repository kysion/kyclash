//go:build darwin && kyclash_utun

// kyclash-vm-utun-lab-harness is the fixed, root-only real-utun bridge for
// the explicitly selected disposable Virtualization.framework VM. It is a
// lab fixture, never an application resource or production helper.
package main

import (
	"bufio"
	"context"
	"encoding/json"
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

	"github.com/kysion/kyclash/network-sidecar/internal/bootstrap"
	"github.com/kysion/kyclash/network-sidecar/internal/ipc"
	"github.com/kysion/kyclash/network-sidecar/internal/labserver"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/userspace"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/unix"
)

const (
	socketPath        = "/var/run/net.kysion.kyclash.vm-utun-lab.sock"
	runnerEnvironment = "local-virtualization-framework"
	vmConfirmation    = "authorized-kyclash-virtualization-framework-vm"
	runtimeTarget     = "kyclash-macos-lab-work"
	profileID         = "lab.vm-utun.actual-child"
	siteID            = "lab-vm-utun"
	xucredVersion     = 0
)

type labHandshake struct {
	ProtocolVersion uint8           `json:"protocol_version"`
	InstanceID      string          `json:"instance_id"`
	AuthProof       string          `json:"auth_proof"`
	LabProfile      profile.Profile `json:"lab_profile"`
	CancelEndpoint  string          `json:"cancel_endpoint"`
}

type runtimeFacts struct {
	goos              string
	goarch            string
	effectiveUID      int
	model             string
	runnerEnvironment string
	confirmation      string
	runtimeTarget     string
	consoleUID        int
}

type socketIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
}

func validateArguments(arguments []string) error {
	if len(arguments) != 0 {
		return errors.New("command-line arguments are not accepted")
	}
	return nil
}

func validateRuntimeFacts(facts runtimeFacts) error {
	if facts.goos != "darwin" || facts.goarch != "arm64" || facts.effectiveUID != 0 {
		return errors.New("root arm64 macOS is required")
	}
	if !strings.HasPrefix(strings.TrimSpace(facts.model), "VirtualMac") {
		return errors.New("a disposable VirtualMac guest is required")
	}
	if facts.runnerEnvironment != runnerEnvironment || facts.confirmation != vmConfirmation || facts.runtimeTarget != runtimeTarget {
		return errors.New("the exact disposable-VM confirmation is required")
	}
	if facts.consoleUID <= 0 {
		return errors.New("a non-root console user is required")
	}
	return nil
}

func consoleIdentity() (int, int, error) {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return 0, 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid == 0 {
		return 0, 0, errors.New("console is not owned by an interactive user")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func requireGuestRuntime(consoleUID int) error {
	model, err := exec.Command("/usr/sbin/sysctl", "-n", "hw.model").Output()
	if err != nil {
		return errors.New("cannot identify VM hardware")
	}
	facts := runtimeFacts{
		goos:              runtime.GOOS,
		goarch:            runtime.GOARCH,
		effectiveUID:      os.Geteuid(),
		model:             string(model),
		runnerEnvironment: os.Getenv("KYCLASH_RUNNER_ENVIRONMENT"),
		confirmation:      os.Getenv("KYCLASH_VM_LAB_CONFIRM"),
		runtimeTarget:     os.Getenv("KYCLASH_RUNTIME_TARGET"),
		consoleUID:        consoleUID,
	}
	return validateRuntimeFacts(facts)
}

func requireProtectedSocketParent() error {
	parent := filepath.Dir(socketPath)
	// macOS exposes /var/run as the stable symlink /private/var/run. Follow
	// that system-owned link for the directory identity check; refusing all
	// symlinks here would reject the documented Darwin path itself.
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || filepath.Clean(resolved) != "/private/var/run" {
		return errors.New("fixed socket parent is unavailable")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return errors.New("fixed socket parent is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("fixed socket parent is not root protected")
	}
	return nil
}

func identifySocket(path string, expectedUID uint32) (socketIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return socketIdentity{}, errors.New("lab socket identity is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID {
		return socketIdentity{}, errors.New("lab socket owner is invalid")
	}
	return socketIdentity{device: uint64(stat.Dev), inode: stat.Ino, uid: stat.Uid}, nil
}

func listenForConsoleUser(consoleUID, consoleGID int) (*net.UnixListener, socketIdentity, error) {
	if consoleUID <= 0 || consoleGID < 0 {
		return nil, socketIdentity{}, errors.New("invalid console identity")
	}
	if err := requireProtectedSocketParent(); err != nil {
		return nil, socketIdentity{}, err
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		return nil, socketIdentity{}, errors.New("lab socket path already exists")
	}
	address, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, socketIdentity{}, err
	}
	previousMask := unix.Umask(0o077)
	listener, err := net.ListenUnix("unix", address)
	unix.Umask(previousMask)
	if err != nil {
		return nil, socketIdentity{}, err
	}
	failed := true
	defer func() {
		if failed {
			_ = listener.Close()
			_ = os.Remove(socketPath)
		}
	}()
	if err := os.Chown(socketPath, consoleUID, consoleGID); err != nil {
		return nil, socketIdentity{}, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return nil, socketIdentity{}, err
	}
	identity, err := identifySocket(socketPath, uint32(consoleUID))
	if err != nil {
		return nil, socketIdentity{}, err
	}
	failed = false
	return listener, identity, nil
}

func removeOwnedSocket(identity socketIdentity) {
	current, err := identifySocket(socketPath, identity.uid)
	if err != nil || current != identity {
		return
	}
	_ = os.Remove(socketPath)
}

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *unix.Xucred
	var socketErr error
	if err := raw.Control(func(descriptor uintptr) {
		credentials, socketErr = unix.GetsockoptXucred(int(descriptor), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil || credentials == nil || credentials.Version != xucredVersion {
		return 0, errors.New("cannot authenticate socket peer")
	}
	return credentials.Uid, nil
}

func makeProfile(cluster *labserver.Cluster) profile.Profile {
	return profile.Profile{
		SchemaVersion: profile.SchemaVersion,
		ProfileID:     profileID,
		ControlPlane:  "https://127.0.0.1/vm-utun-lab",
		IdentityRef:   "keychain:net.kysion.kyclash.test.vm-utun-lab",
		Site: profile.Site{
			ID:           siteID,
			DisplayName:  "KyClash VM lab · real utun · no routes",
			PrivateCIDRs: []string{"10.88.0.2/32"},
		},
		Tunnel: profile.Tunnel{
			LocalAddresses:   []string{"10.88.0.1/32"},
			PeerPublicKey:    cluster.PeerPublicKey(),
			KeepaliveSeconds: 5,
		},
		Transports: profile.Transports{
			Primary:   profile.QUIC,
			Fallbacks: []profile.Transport{profile.WSS, profile.TCP},
			Endpoints: cluster.Endpoints(),
		},
		Policy: profile.Policy{
			ConnectTimeoutSeconds: 5,
			HealthIntervalSeconds: 1,
			FallbackThreshold:     1,
		},
	}
}

func serveOne(ctx context.Context, connection *net.UnixConn) error {
	defer connection.Close()
	reader := bufio.NewReaderSize(connection, 64*1_024)
	config, err := bootstrap.DecodeLine(reader)
	if err != nil {
		return err
	}
	defer config.Clear()
	clientPublic, err := curve25519.X25519(config.PrivateKey, curve25519.Basepoint)
	if err != nil {
		return err
	}
	cluster, err := labserver.StartCluster(ctx, clientPublic)
	clear(clientPublic)
	if err != nil {
		return err
	}
	defer cluster.Close()
	networkProfile := makeProfile(cluster)
	if err := networkProfile.Validate(); err != nil {
		return err
	}
	// New (rather than NewLab) intentionally disables the userspace-netstack
	// payload probe. With kyclash_utun the backend owns a Darwin utun and still
	// exercises the authenticated carrier ping/pong health path.
	backend, err := userspace.New(config.PrivateKey, cluster.Roots(), config.InstanceID)
	if err != nil {
		return err
	}
	proof := bootstrap.AuthProof(config)
	response := labHandshake{
		ProtocolVersion: bootstrap.ProtocolVersion,
		InstanceID:      config.InstanceID,
		AuthProof:       proof,
		LabProfile:      networkProfile,
		CancelEndpoint:  "https://127.0.0.1/vm-utun-lab/cancel-disabled",
	}
	config.Clear()
	if err := json.NewEncoder(connection).Encode(response); err != nil {
		_ = backend.Close()
		return errors.New("write authenticated lab handshake")
	}
	return ipc.ServeWithBackendContext(ctx, reader, connection, connection, backend)
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
	listener, identity, err := listenForConsoleUser(consoleUID, consoleGID)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer removeOwnedSocket(identity)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	connection, err := listener.AcceptUnix()
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	// Closing the listener immediately makes this an exact one-connection
	// harness. It can never become a reusable root daemon.
	_ = listener.Close()
	uid, err := peerUID(connection)
	if err != nil || uid != uint32(consoleUID) {
		_ = connection.Close()
		return errors.New("lab socket peer refused")
	}
	return serveOne(ctx, connection)
}

func execute(arguments []string, stderr io.Writer) int {
	if err := run(arguments); err != nil {
		_, _ = fmt.Fprintln(stderr, "KyClash VM utun lab harness failed")
		return 1
	}
	return 0
}

func main() { os.Exit(execute(os.Args[1:], os.Stderr)) }
