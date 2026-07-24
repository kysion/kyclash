//go:build darwin && kyclash_utun && kyclash_vm_network_lab

// kyclash-vm-network-lab-harness is the fixed, root-only core-network fixture
// for the selected disposable Virtualization.framework guest. It is not a
// production helper and accepts no caller-controlled route, path, endpoint,
// command, or profile field.
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
	"github.com/kysion/kyclash/network-sidecar/internal/vmnetworklab"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/unix"
)

const xucredVersion = 0

type vmNetworkHandshake struct {
	ProtocolVersion uint8           `json:"protocol_version"`
	InstanceID      string          `json:"instance_id"`
	AuthProof       string          `json:"auth_proof"`
	LabProfile      profile.Profile `json:"lab_profile"`
	RuntimeMode     string          `json:"runtime_mode"`
	TunnelKind      string          `json:"tunnel_kind"`
	TunnelInterface *string         `json:"tunnel_interface"`
	MihomoDevice    string          `json:"mihomo_device"`
	CancelEndpoint  string          `json:"cancel_endpoint"`
}

type runtimeFacts struct {
	goos, goarch, model, runner, confirmation, target string
	effectiveUID, consoleUID                          int
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
	if facts.goos != "darwin" || facts.goarch != "arm64" || facts.effectiveUID != 0 || facts.consoleUID <= 0 {
		return errors.New("root arm64 macOS with an interactive console user is required")
	}
	if !strings.HasPrefix(strings.TrimSpace(facts.model), "VirtualMac") {
		return errors.New("a disposable VirtualMac guest is required")
	}
	if facts.runner != vmnetworklab.RunnerEnv || facts.confirmation != vmnetworklab.VMConfirmation || facts.target != vmnetworklab.RuntimeTarget {
		return errors.New("the exact disposable-VM confirmation is required")
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
	return validateRuntimeFacts(runtimeFacts{
		goos: runtime.GOOS, goarch: runtime.GOARCH, effectiveUID: os.Geteuid(),
		model: string(model), runner: os.Getenv("KYCLASH_RUNNER_ENVIRONMENT"),
		confirmation: os.Getenv("KYCLASH_VM_LAB_CONFIRM"), target: os.Getenv("KYCLASH_RUNTIME_TARGET"),
		consoleUID: consoleUID,
	})
}

func requireFixedSelf() error {
	executable, err := os.Executable()
	if err != nil || filepath.Clean(executable) != vmnetworklab.HarnessPath {
		return errors.New("harness is not running from the fixed root stage")
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil || resolved != vmnetworklab.HarnessPath {
		return errors.New("harness executable path is redirected")
	}
	info, err := os.Lstat(executable)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o500 {
		return errors.New("harness executable identity is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return errors.New("harness executable is not uniquely root-owned")
	}
	return nil
}

func ensureStateRoot() error {
	parent := filepath.Dir(vmnetworklab.StateRoot)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != "/private/var/tmp" {
		return errors.New("fixed state parent is unavailable")
	}
	if err := os.Mkdir(vmnetworklab.StateRoot, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(vmnetworklab.StateRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("fixed state root is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("fixed state root is not root-owned")
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
	if _, err := os.Lstat(vmnetworklab.SocketPath); !errors.Is(err, os.ErrNotExist) {
		return nil, socketIdentity{}, errors.New("lab socket path already exists")
	}
	address, err := net.ResolveUnixAddr("unix", vmnetworklab.SocketPath)
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
			_ = os.Remove(vmnetworklab.SocketPath)
		}
	}()
	if err := os.Chown(vmnetworklab.SocketPath, consoleUID, consoleGID); err != nil {
		return nil, socketIdentity{}, err
	}
	if err := os.Chmod(vmnetworklab.SocketPath, 0o600); err != nil {
		return nil, socketIdentity{}, err
	}
	identity, err := identifySocket(vmnetworklab.SocketPath, uint32(consoleUID))
	if err != nil {
		return nil, socketIdentity{}, err
	}
	failed = false
	return listener, identity, nil
}

func removeOwnedSocket(identity socketIdentity) {
	current, err := identifySocket(vmnetworklab.SocketPath, identity.uid)
	if err == nil && current == identity {
		_ = os.Remove(vmnetworklab.SocketPath)
	}
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
		ProfileID:     vmnetworklab.ProfileID,
		ControlPlane:  "https://127.0.0.1/vm-network-lab",
		IdentityRef:   "keychain:net.kysion.kyclash.test.vm-network-lab",
		Site:          profile.Site{ID: vmnetworklab.SiteID, DisplayName: "KyClash VM lab · real utun · private route · Mihomo", PrivateCIDRs: []string{vmnetworklab.PrivateCIDR}},
		Tunnel:        profile.Tunnel{LocalAddresses: []string{vmnetworklab.ClientCIDR}, PeerPublicKey: cluster.PeerPublicKey(), KeepaliveSeconds: 5},
		Transports:    profile.Transports{Primary: profile.QUIC, Fallbacks: []profile.Transport{profile.WSS, profile.TCP}, Endpoints: cluster.Endpoints()},
		Policy:        profile.Policy{ConnectTimeoutSeconds: 5, HealthIntervalSeconds: 1, FallbackThreshold: 1},
	}
}

func serveOne(
	ctx context.Context,
	connection *net.UnixConn,
	routes *vmnetworklab.RouteCoordinator,
	coexistence *vmnetworklab.RuntimeCoexistenceVerifier,
) error {
	defer connection.Close()
	reader := bufio.NewReaderSize(connection, 64*1024)
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
	backend, err := vmnetworklab.NewBackend(config.PrivateKey, cluster.Roots(), config.InstanceID, routes, coexistence)
	if err != nil {
		return err
	}
	proof := bootstrap.AuthProof(config)
	handshake := vmNetworkHandshake{
		ProtocolVersion: bootstrap.ProtocolVersion, InstanceID: config.InstanceID, AuthProof: proof,
		LabProfile: networkProfile, RuntimeMode: vmnetworklab.RuntimeMode, TunnelKind: vmnetworklab.TunnelKind,
		TunnelInterface: nil, MihomoDevice: vmnetworklab.MihomoInterface,
		CancelEndpoint: "https://127.0.0.1/vm-network-lab/cancel-disabled",
	}
	config.Clear()
	if err := json.NewEncoder(connection).Encode(handshake); err != nil {
		_ = backend.Close()
		return errors.New("write authenticated VM network handshake")
	}
	return ipc.ServeWithBackendContext(ctx, reader, connection, connection, backend)
}

func run(arguments []string) (runErr error) {
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
	if err := requireFixedSelf(); err != nil {
		return err
	}
	if err := ensureStateRoot(); err != nil {
		return err
	}
	inspector := vmnetworklab.DarwinRouteInspector{}
	executor := vmnetworklab.DarwinRouteExecutor{}
	store := vmnetworklab.NewJournalStore(vmnetworklab.JournalPath, true)
	baseline, err := vmnetworklab.CaptureSystemSnapshot(inspector)
	if err != nil {
		return err
	}
	if retained, exists, err := store.Load(); err != nil {
		return err
	} else if exists {
		if err := vmnetworklab.RecoverJournal(context.Background(), store, retained, inspector, executor, baseline); err != nil {
			return err
		}
		baseline, err = vmnetworklab.CaptureSystemSnapshot(inspector)
		if err != nil {
			return err
		}
	}
	if err := vmnetworklab.ValidateForeignAbsence(baseline.Routes); err != nil {
		return err
	}
	routes := vmnetworklab.NewRouteCoordinator(store, inspector, executor)
	record := routes.Record()
	if err := routes.SetMihomo(record); err != nil {
		return err
	}
	mihomo := vmnetworklab.NewMihomoManager(inspector)
	defer func() {
		if err := mihomo.Stop(context.Background()); err != nil {
			_ = routes.MarkRecoveryOnly()
			runErr = errors.Join(runErr, err)
			return
		}
		finalRecord := routes.Record()
		if err := routes.Finalize(func() error {
			return vmnetworklab.VerifyFinalAbsence(inspector, baseline, finalRecord.TunnelInterface)
		}); err != nil {
			_ = routes.MarkRecoveryOnly()
			runErr = errors.Join(runErr, err)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := mihomo.Start(ctx); err != nil {
		return err
	}
	record = routes.Record()
	record.MihomoChild = mihomo.Identity()
	if err := routes.SetMihomo(record); err != nil {
		return err
	}
	if err := routes.Preflight(); err != nil {
		return err
	}
	coexistence, err := vmnetworklab.NewRuntimeCoexistenceVerifier(mihomo, routes, inspector, baseline)
	if err != nil {
		return err
	}
	listener, socketID, err := listenForConsoleUser(consoleUID, consoleGID)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer removeOwnedSocket(socketID)
	go func() { <-ctx.Done(); _ = listener.Close() }()
	connection, err := listener.AcceptUnix()
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	_ = listener.Close()
	uid, err := peerUID(connection)
	if err != nil || uid != uint32(consoleUID) {
		_ = connection.Close()
		return errors.New("lab socket peer refused")
	}
	return serveOne(ctx, connection, routes, coexistence)
}

func execute(arguments []string, stderr io.Writer) int {
	if err := run(arguments); err != nil {
		_, _ = fmt.Fprintln(stderr, "KyClash VM network lab harness failed")
		return 1
	}
	return 0
}

func main() { os.Exit(execute(os.Args[1:], os.Stderr)) }
