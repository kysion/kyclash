//go:build darwin && kyclash_utun && (kyclash_vm_network_lab || kyclash_vm_external_peer_lab)

package vmnetworklab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	mihomoReadyTimeout = 20 * time.Second
	mihomoPollInterval = 100 * time.Millisecond
	processStopTimeout = 5 * time.Second
)

type MihomoSnapshot struct {
	PID          int
	Device       string
	InterfaceIdx int
	Covering     bool
	Config       MihomoConfigFacts
}

type MihomoConfigFacts struct {
	TUNEnabled bool
	Device     string
}

type MihomoManager struct {
	inspector RouteInspector
	contract  MihomoContract
	command   *exec.Cmd
	identity  ProcessIdentity
	fileID    fileIdentity
	started   bool
}

func NewMihomoManager(inspector RouteInspector) *MihomoManager {
	return NewMihomoManagerWithContract(inspector, DefaultMihomoContract())
}

func NewMihomoManagerWithContract(inspector RouteInspector, contract MihomoContract) *MihomoManager {
	return &MihomoManager{inspector: inspector, contract: contract}
}

func (manager *MihomoManager) Identity() ProcessIdentity {
	return manager.identity
}

// AdoptForRecovery binds only an exact journaled process identity. It never
// starts a child and is available solely before the harness opens its App
// socket.
func (manager *MihomoManager) AdoptForRecovery(identity ProcessIdentity) error {
	if manager.started || identity.PID <= 1 || manager.inspector == nil {
		return ErrMihomoIdentity
	}
	if !manager.contract.valid() {
		return ErrMihomoIdentity
	}
	digest, fileID, err := validateMihomoExecutable(manager.contract.Executable, true)
	if err != nil || digest != identity.SHA256 || fileID.dev != identity.Dev || fileID.inode != identity.Inode {
		return ErrMihomoIdentity
	}
	manager.identity = identity
	manager.fileID = fileID
	manager.started = true
	if !manager.processMatches() {
		manager.started = false
		return ErrMihomoIdentity
	}
	return nil
}

func (manager *MihomoManager) Start(ctx context.Context) error {
	if manager.started || manager.command != nil || manager.inspector == nil || !manager.contract.valid() {
		return ErrMihomoIdentity
	}
	if err := validateRootDirectory(manager.contract.StageRoot, 0o700); err != nil {
		return err
	}
	if err := validateRootDirectory(manager.contract.StateRoot, manager.contract.StateRootMode); err != nil {
		return err
	}
	if err := validateMihomoConfigFile(manager.contract.ConfigPath, true, manager.contract); err != nil {
		return err
	}
	if _, _, err := validateMihomoExecutable(manager.contract.Executable, true); err != nil {
		return err
	}
	if err := validateMachOArm64(manager.contract.Executable); err != nil {
		return err
	}
	if info, err := os.Lstat(manager.contract.SocketPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
			return ErrMihomoIdentity
		}
		return errors.New("fixed Mihomo socket already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	digest, fileID, err := validateMihomoExecutable(manager.contract.Executable, true)
	if err != nil {
		return err
	}
	command := exec.Command(manager.contract.Executable, "-d", manager.contract.StageRoot, "-f", manager.contract.ConfigPath, "-ext-ctl-unix", manager.contract.SocketPath)
	command.Env = []string{}
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return ErrMihomoIdentity
	}
	manager.command = command
	manager.fileID = fileID
	manager.identity = ProcessIdentity{PID: command.Process.Pid, SHA256: digest, Dev: fileID.dev, Inode: fileID.inode}
	startTime, err := processStartTime(command.Process.Pid)
	if err != nil {
		_ = manager.killAndWait(context.Background())
		return ErrMihomoIdentity
	}
	manager.identity.StartTime = startTime
	manager.started = true
	if err := manager.waitReady(ctx); err != nil {
		_ = manager.Stop(context.Background())
		return err
	}
	return nil
}

func (manager *MihomoManager) waitReady(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := time.NewTimer(mihomoReadyTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(mihomoPollInterval)
	defer ticker.Stop()
	for {
		err := manager.secureControllerSocket()
		var snapshot MihomoSnapshot
		if err == nil {
			snapshot, err = manager.Snapshot(ctx)
		}
		if err == nil && snapshot.Config.TUNEnabled && snapshot.Config.Device == MihomoInterface && snapshot.Device == MihomoInterface && snapshot.Covering {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("Mihomo fixture did not become ready")
		case <-ticker.C:
		}
	}
}

func (manager *MihomoManager) Snapshot(ctx context.Context) (MihomoSnapshot, error) {
	if !manager.started || !manager.processMatches() {
		return MihomoSnapshot{}, ErrMihomoIdentity
	}
	if err := manager.requireControllerSocket(); err != nil {
		return MihomoSnapshot{}, err
	}
	config, err := manager.fetchConfig(ctx)
	if err != nil {
		return MihomoSnapshot{}, err
	}
	interfaceValue, err := net.InterfaceByName(MihomoInterface)
	if err != nil || interfaceValue.Index <= 0 {
		return MihomoSnapshot{}, errors.New("Mihomo TUN device is absent")
	}
	routes, err := manager.inspector.Snapshot()
	if err != nil {
		return MihomoSnapshot{}, err
	}
	covering := false
	for _, entry := range routes.IPv4 {
		if entry.Prefix.Masked() == CoveringPrefix() && entry.Interface == MihomoInterface {
			if covering {
				return MihomoSnapshot{}, errors.New("duplicate Mihomo covering route")
			}
			covering = true
		}
	}
	return MihomoSnapshot{PID: manager.identity.PID, Device: MihomoInterface, InterfaceIdx: interfaceValue.Index, Covering: covering, Config: config}, nil
}

func (manager *MihomoManager) controllerSocketIdentity() (fileIdentity, os.FileInfo, error) {
	info, err := os.Lstat(manager.contract.SocketPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || !isRootOwned(info) {
		return fileIdentity{}, nil, ErrMihomoIdentity
	}
	identity, err := getFileIdentity(info)
	if err != nil {
		return fileIdentity{}, nil, ErrMihomoIdentity
	}
	return identity, info, nil
}

func (manager *MihomoManager) requireControllerSocket() error {
	_, info, err := manager.controllerSocketIdentity()
	if err != nil || info.Mode().Perm() != 0o600 {
		return ErrMihomoIdentity
	}
	return nil
}

func (manager *MihomoManager) secureControllerSocket() error {
	if !manager.started || !manager.processMatches() {
		return ErrMihomoIdentity
	}
	before, info, err := manager.controllerSocketIdentity()
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o600 {
		if err := os.Chmod(manager.contract.SocketPath, 0o600); err != nil {
			return ErrMihomoIdentity
		}
	}
	after, _, err := manager.controllerSocketIdentity()
	if err != nil || before != after {
		return ErrMihomoIdentity
	}
	return manager.requireControllerSocket()
}

func (manager *MihomoManager) fetchConfig(ctx context.Context) (MihomoConfigFacts, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", manager.contract.SocketPath)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/configs", nil)
	if err != nil {
		return MihomoConfigFacts{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return MihomoConfigFacts{}, errors.New("Mihomo controller unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return MihomoConfigFacts{}, errors.New("Mihomo controller rejected config query")
	}
	limited := io.LimitReader(response.Body, 1<<20)
	var root map[string]json.RawMessage
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(&root); err != nil {
		return MihomoConfigFacts{}, errors.New("Mihomo config response malformed")
	}
	tunBytes, ok := root["tun"]
	if !ok {
		return MihomoConfigFacts{}, errors.New("Mihomo config response lacks TUN facts")
	}
	var tun struct {
		Enable bool   `json:"enable"`
		Device string `json:"device"`
	}
	if err := json.Unmarshal(tunBytes, &tun); err != nil || tun.Device == "" {
		return MihomoConfigFacts{}, errors.New("Mihomo TUN facts malformed")
	}
	return MihomoConfigFacts{TUNEnabled: tun.Enable, Device: tun.Device}, nil
}

func (manager *MihomoManager) processMatches() bool {
	if manager.identity.PID <= 1 {
		return false
	}
	if err := syscall.Kill(manager.identity.PID, 0); err != nil {
		return false
	}
	startTime, err := processStartTime(manager.identity.PID)
	if err != nil || startTime != manager.identity.StartTime {
		return false
	}
	path, err := processCommandPath(manager.identity.PID)
	if err != nil || path != manager.contract.Executable {
		return false
	}
	return true
}

func (manager *MihomoManager) Stop(ctx context.Context) error {
	if !manager.started {
		return nil
	}
	if !manager.processMatches() {
		return ErrMihomoIdentity
	}
	if err := manager.killAndWait(ctx); err != nil {
		return err
	}
	if err := manager.verifyAbsence(); err != nil {
		return err
	}
	manager.command = nil
	manager.started = false
	return nil
}

func (manager *MihomoManager) killAndWait(ctx context.Context) error {
	if manager.identity.PID <= 1 {
		return ErrMihomoIdentity
	}
	if manager.command == nil || manager.command.Process == nil {
		if err := syscall.Kill(manager.identity.PID, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			return ErrMihomoIdentity
		}
		deadline := time.Now().Add(processStopTimeout)
		for time.Now().Before(deadline) {
			if err := syscall.Kill(manager.identity.PID, 0); errors.Is(err, syscall.ESRCH) {
				return nil
			}
			if ctx != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
			}
			time.Sleep(mihomoPollInterval)
		}
		if !manager.processMatches() {
			return nil
		}
		if err := syscall.Kill(manager.identity.PID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return ErrMihomoIdentity
		}
		deadline = time.Now().Add(processStopTimeout)
		for time.Now().Before(deadline) {
			if err := syscall.Kill(manager.identity.PID, 0); errors.Is(err, syscall.ESRCH) {
				return nil
			}
			time.Sleep(mihomoPollInterval)
		}
		return errors.New("recovered Mihomo process did not exit")
	}
	if err := manager.command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return ErrMihomoIdentity
	}
	wait := make(chan error, 1)
	go func() { wait <- manager.command.Wait() }()
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(processStopTimeout)
	defer timer.Stop()
	select {
	case <-wait:
		return nil
	case <-ctx.Done():
		_ = manager.command.Process.Kill()
		return ctx.Err()
	case <-timer.C:
		_ = manager.command.Process.Kill()
		select {
		case <-wait:
			return nil
		case <-time.After(processStopTimeout):
			return errors.New("Mihomo process did not exit")
		}
	}
}

func (manager *MihomoManager) verifyAbsence() error {
	if manager.processMatches() {
		return ErrMihomoIdentity
	}
	if _, err := net.InterfaceByName(MihomoInterface); err == nil {
		return errors.New("Mihomo TUN device remained")
	}
	if routes, err := manager.inspector.Snapshot(); err != nil {
		return err
	} else {
		for _, entry := range routes.IPv4 {
			if entry.Prefix.Masked() == CoveringPrefix() && entry.Interface == MihomoInterface {
				return errors.New("Mihomo covering route remained")
			}
		}
	}
	if info, err := os.Lstat(manager.contract.SocketPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || !isRootOwned(info) || info.Mode().Perm() != 0o600 {
			return ErrMihomoIdentity
		}
		if err := os.Remove(manager.contract.SocketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func validateRootDirectory(path string, expectedMode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != expectedMode || !isRootOwned(info) {
		return fmt.Errorf("unsafe fixed root directory: %s", filepath.Base(path))
	}
	return nil
}

func processStartTime(pid int) (string, error) {
	output, err := exec.Command("/bin/ps", "-p", strconv.Itoa(pid), "-o", "lstart=").Output()
	if err != nil {
		return "", ErrMihomoIdentity
	}
	value := strings.TrimSpace(string(output))
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", ErrMihomoIdentity
	}
	return value, nil
}

func processCommandPath(pid int) (string, error) {
	output, err := exec.Command("/bin/ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return "", ErrMihomoIdentity
	}
	value := strings.TrimSpace(string(output))
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", ErrMihomoIdentity
	}
	fields := strings.Fields(value)
	if len(fields) == 0 || !filepath.IsAbs(fields[0]) {
		return "", ErrMihomoIdentity
	}
	return fields[0], nil
}
