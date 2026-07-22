//go:build darwin && kyclash_utun && kyclash_utun_lab

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/bootstrap"
	"github.com/kysion/kyclash/network-sidecar/internal/ipc"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"golang.org/x/crypto/curve25519"
)

const (
	utunLabConfirmation        = "authorized-kyclash-virtualization-framework-vm"
	utunLabCombinedHoldEnv     = "KYCLASH_UTUN_LAB_COMBINED_HOLD"
	utunLabCombinedEvidenceEnv = "KYCLASH_UTUN_LAB_COMBINED_EVIDENCE_FILE"
	utunLabChildEnv            = "KYCLASH_UTUN_LAB_PRODUCTION_CHILD"
	utunLabChildConfirmation   = "production-run-v1"
	utunLabEvidenceDirectory   = "/var/tmp"
	utunLabEvidenceBasePrefix  = "kyclash-utun-lab-"
	utunLabInstanceID          = "instance-utun-stdin"
	utunLabProfileRequestID    = "request.stdin.profile"
	utunLabPrepareRequestID    = "request.stdin.prepare"
)

func TestRealUTUNStdinEOFAndMalformedIPCFinalAbsence(t *testing.T) {
	requireDisposableVirtualMac(t)
	for _, testCase := range []struct {
		name      string
		trailer   string
		wantError bool
	}{
		{name: "stdin_eof"},
		{name: "malformed_ipc", trailer: "{malformed\n", wantError: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			input := realUTUNInput(t, testCase.trailer)
			var output bytes.Buffer
			err := run(nil, strings.NewReader(input), &output)
			if testCase.wantError != (err != nil) {
				t.Fatalf("run error = %v, wantError %v", err, testCase.wantError)
			}
			interfaceName := preparedInterface(t, output.Bytes())
			if _, err := net.InterfaceByName(interfaceName); err == nil {
				t.Fatalf("owned interface %s remained after %s", interfaceName, testCase.name)
			}
		})
	}
}

// TestRealUTUNProductionSidecarControllerHoldForForcedTermination is the
// controller half of the exact production run()/real-utun cleanup fixture. It
// deliberately never returns after publishing ownership evidence: the
// disposable-VM harness must SIGKILL this controller process, which closes its
// pipe and reparents the child. The child then exercises the same EOF/parent
// cancellation and backend.Close path as the shipped sidecar.
func TestRealUTUNProductionSidecarControllerHoldForForcedTermination(t *testing.T) {
	if os.Getenv(utunLabCombinedHoldEnv) != "1" {
		t.Skip("combined production-sidecar fixture is enabled only by the disposable-VM harness")
	}
	requireDisposableVirtualMac(t)
	evidencePath, err := validateUTUNLabEvidencePath(os.Getenv(utunLabCombinedEvidenceEnv))
	if err != nil {
		t.Fatal(err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal("resolve exact production sidecar fixture executable")
	}
	command := exec.Command(executable,
		"-test.run=^TestRealUTUNProductionSidecarChild$",
		"-test.count=1",
		"-test.v=false",
	)
	command.Env = replaceEnvironmentValue(os.Environ(), utunLabChildEnv, utunLabChildConfirmation)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		_ = stdin.Close()
		_ = command.Process.Kill()
		<-wait
	}()

	input := realUTUNInput(t, "")
	if _, err := io.WriteString(stdin, input); err != nil {
		t.Fatal("write production sidecar fixture input")
	}
	input = ""
	interfaceName, err := readProductionPreparedInterface(bufio.NewReader(stdout))
	if err != nil {
		t.Fatalf("read production sidecar fixture response: %v", err)
	}
	if _, err := net.InterfaceByName(interfaceName); err != nil {
		t.Fatalf("prepared interface %s is absent before controller termination", interfaceName)
	}
	if err := writeUTUNLabControllerEvidence(evidencePath, interfaceName, command.Process.Pid); err != nil {
		t.Fatal(err)
	}

	// Keep stdin open and retain the direct child relationship. An external
	// SIGKILL of this exact controller is the event under test.
	err = <-wait
	cleanup = false
	if err == nil {
		t.Fatal("production sidecar child exited before controller termination")
	}
	t.Fatal("production sidecar child failed before controller termination")
}

// TestRealUTUNProductionSidecarChild is never invoked directly by the lab
// harness. The controller starts this exact helper in a separate process so it
// runs the production entrypoint with real os.Stdin/os.Stdout process pipes.
func TestRealUTUNProductionSidecarChild(t *testing.T) {
	if os.Getenv(utunLabChildEnv) != utunLabChildConfirmation {
		t.Skip("production sidecar child is controller-owned")
	}
	requireDisposableVirtualMac(t)
	if err := run(nil, os.Stdin, os.Stdout); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal("production sidecar child failed")
	}
}

func TestValidateUTUNLabEvidencePath(t *testing.T) {
	valid := []string{
		"/var/tmp/kyclash-utun-lab-combined-20260722",
		"/var/tmp/kyclash-utun-lab-run_01.evidence",
	}
	for _, path := range valid {
		if got, err := validateUTUNLabEvidencePath(path); err != nil || got != path {
			t.Errorf("validateUTUNLabEvidencePath(%q) = %q, %v", path, got, err)
		}
	}
	invalid := []string{
		"",
		"kyclash-utun-lab-relative",
		"/tmp/kyclash-utun-lab-wrong-directory",
		"/var/tmp/kyclash-utun-lab-",
		"/var/tmp/kyclash-utun-lab-nested/path",
		"/var/tmp/kyclash-utun-lab-../escape",
		"/var/tmp/kyclash-utun-lab-invalid space",
		"/var/tmp/kyclash-utun-lab-invalid\nline",
		"/var/tmp/not-kyclash-evidence",
	}
	for _, path := range invalid {
		if _, err := validateUTUNLabEvidencePath(path); err == nil {
			t.Errorf("validateUTUNLabEvidencePath(%q) succeeded", path)
		}
	}
}

func TestEncodeUTUNLabControllerEvidence(t *testing.T) {
	encoded, err := encodeUTUNLabControllerEvidence("utun17", 4242)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "utun17\n4242\n" {
		t.Fatalf("unexpected evidence: %q", encoded)
	}
	for _, testCase := range []struct {
		name          string
		interfaceName string
		pid           int
	}{
		{name: "missing suffix", interfaceName: "utun", pid: 2},
		{name: "noncanonical suffix", interfaceName: "utun01", pid: 2},
		{name: "shell characters", interfaceName: "utun1;id", pid: 2},
		{name: "newline", interfaceName: "utun1\n2", pid: 2},
		{name: "init pid", interfaceName: "utun1", pid: 1},
		{name: "negative pid", interfaceName: "utun1", pid: -1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := encodeUTUNLabControllerEvidence(testCase.interfaceName, testCase.pid); err == nil {
				t.Fatal("invalid evidence succeeded")
			}
		})
	}
}

func TestReadProductionPreparedInterfaceRequiresExactOwnership(t *testing.T) {
	validFacts := ipc.TunnelDeviceFacts{
		InterfaceName: "utun17",
		MTU:           profile.TunnelMTU,
		HasIPv4:       true,
		HasIPv6:       true,
		InstanceID:    utunLabInstanceID,
		OperationID:   utunLabPrepareRequestID,
	}
	output := productionPreparedOutput(t, validFacts)
	if got, err := readProductionPreparedInterface(bufio.NewReader(bytes.NewReader(output))); err != nil || got != "utun17" {
		t.Fatalf("readProductionPreparedInterface() = %q, %v", got, err)
	}

	for _, testCase := range []struct {
		name   string
		mutate func(*ipc.TunnelDeviceFacts)
	}{
		{name: "invalid name", mutate: func(facts *ipc.TunnelDeviceFacts) { facts.InterfaceName = "utun17\n18" }},
		{name: "wrong instance", mutate: func(facts *ipc.TunnelDeviceFacts) { facts.InstanceID = "instance.other" }},
		{name: "wrong operation", mutate: func(facts *ipc.TunnelDeviceFacts) { facts.OperationID = "request.other" }},
		{name: "wrong mtu", mutate: func(facts *ipc.TunnelDeviceFacts) { facts.MTU-- }},
		{name: "missing ipv4", mutate: func(facts *ipc.TunnelDeviceFacts) { facts.HasIPv4 = false }},
		{name: "missing ipv6", mutate: func(facts *ipc.TunnelDeviceFacts) { facts.HasIPv6 = false }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			facts := validFacts
			testCase.mutate(&facts)
			if _, err := readProductionPreparedInterface(bufio.NewReader(bytes.NewReader(productionPreparedOutput(t, facts)))); err == nil {
				t.Fatal("non-owned prepare response succeeded")
			}
		})
	}
}

func requireDisposableVirtualMac(t *testing.T) {
	t.Helper()
	if os.Getenv("KYCLASH_VM_LAB_CONFIRM") != utunLabConfirmation {
		t.Fatal("real utun lab requires the exact disposable-VM confirmation")
	}
	output, err := exec.Command("/usr/sbin/sysctl", "-n", "hw.model").Output()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(output)), "VirtualMac") {
		t.Fatal("real utun lab refuses non-VirtualMac hosts")
	}
}

func realUTUNInput(t *testing.T, trailer string) string {
	t.Helper()
	private := make([]byte, curve25519.ScalarSize)
	private[0], private[31] = 91, 64
	peerPrivate := make([]byte, curve25519.ScalarSize)
	peerPrivate[0], peerPrivate[31] = 101, 64
	peerPublic, err := curve25519.X25519(peerPrivate, curve25519.Basepoint)
	clear(peerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	config := bootstrap.Config{
		ProtocolVersion: bootstrap.ProtocolVersion,
		InstanceID:      utunLabInstanceID,
		AuthToken:       bytes.Repeat([]byte{0x42}, 32),
		PrivateKey:      private,
	}
	networkProfile := profile.Profile{
		SchemaVersion: profile.SchemaVersion,
		ProfileID:     "utun.stdin.profile",
		ControlPlane:  "https://127.0.0.1/control",
		IdentityRef:   "keychain:net.kysion.kyclash.test.utun",
		Site:          profile.Site{ID: "utun-stdin", DisplayName: "utun stdin", PrivateCIDRs: []string{"10.90.0.2/32"}},
		Tunnel:        profile.Tunnel{LocalAddresses: []string{"10.90.0.1/24", "fd00:90::1/64"}, PeerPublicKey: base64.StdEncoding.EncodeToString(peerPublic), KeepaliveSeconds: 5},
		Transports:    profile.Transports{Primary: profile.QUIC, Fallbacks: []profile.Transport{profile.WSS, profile.TCP}, Endpoints: []profile.Endpoint{{Transport: profile.QUIC, URL: "https://127.0.0.1:443"}, {Transport: profile.WSS, URL: "wss://127.0.0.1:443/kynp"}, {Transport: profile.TCP, URL: "tcp://127.0.0.1:443"}}},
		Policy:        profile.Policy{ConnectTimeoutSeconds: 5, HealthIntervalSeconds: 1, FallbackThreshold: 1},
	}
	clear(peerPublic)
	if err := networkProfile.Validate(); err != nil {
		t.Fatal(err)
	}
	profileData, err := json.Marshal(networkProfile)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapData, err := json.Marshal(config)
	config.Clear()
	if err != nil {
		t.Fatal(err)
	}
	requests := []ipc.Request{
		{ProtocolVersion: ipc.ProtocolVersion, RequestID: utunLabProfileRequestID, Payload: ipc.Payload{Type: "apply_profile", Data: profileData}},
		{ProtocolVersion: ipc.ProtocolVersion, RequestID: utunLabPrepareRequestID, Payload: ipc.Payload{Type: "prepare_tunnel"}},
	}
	var input strings.Builder
	input.Write(bootstrapData)
	input.WriteByte('\n')
	clear(bootstrapData)
	for _, request := range requests {
		encoded, marshalErr := json.Marshal(request)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		input.Write(encoded)
		input.WriteByte('\n')
		clear(encoded)
	}
	input.WriteString(trailer)
	return input.String()
}

func preparedInterface(t *testing.T, output []byte) string {
	t.Helper()
	for _, line := range bytes.Split(bytes.TrimSpace(output), []byte{'\n'}) {
		var response struct {
			RequestID string `json:"request_id"`
			Result    struct {
				OK struct {
					Type string                `json:"type"`
					Data ipc.TunnelDeviceFacts `json:"data"`
				} `json:"Ok"`
			} `json:"result"`
		}
		if json.Unmarshal(line, &response) == nil && response.Result.OK.Type == "tunnel_prepared" {
			if !strings.HasPrefix(response.Result.OK.Data.InterfaceName, "utun") {
				t.Fatal("prepare response did not contain a validated utun")
			}
			return response.Result.OK.Data.InterfaceName
		}
	}
	t.Fatal("missing tunnel_prepared response")
	return ""
}

func readProductionPreparedInterface(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return "", errors.New("missing production sidecar handshake")
	}
	var childHandshake handshake
	if err := json.Unmarshal(bytes.TrimSpace(line), &childHandshake); err != nil ||
		childHandshake.ProtocolVersion != bootstrap.ProtocolVersion ||
		childHandshake.InstanceID != utunLabInstanceID ||
		childHandshake.AuthProof != expectedUTUNLabAuthProof() {
		clear(line)
		return "", errors.New("invalid production sidecar handshake")
	}
	clear(line)

	for _, expected := range []struct {
		requestID string
		result    string
	}{
		{requestID: utunLabProfileRequestID, result: "acknowledged"},
		{requestID: utunLabPrepareRequestID, result: "tunnel_prepared"},
	} {
		line, err = reader.ReadBytes('\n')
		if err != nil {
			return "", fmt.Errorf("missing %s response", expected.requestID)
		}
		var response struct {
			ProtocolVersion uint8  `json:"protocol_version"`
			RequestID       string `json:"request_id"`
			Result          struct {
				OK struct {
					Type string                `json:"type"`
					Data ipc.TunnelDeviceFacts `json:"data"`
				} `json:"Ok"`
			} `json:"result"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(line), &response); err != nil ||
			response.ProtocolVersion != ipc.ProtocolVersion ||
			response.RequestID != expected.requestID ||
			response.Result.OK.Type != expected.result {
			clear(line)
			return "", fmt.Errorf("invalid %s response", expected.requestID)
		}
		clear(line)
		if expected.result != "tunnel_prepared" {
			continue
		}
		facts := response.Result.OK.Data
		if !validLabUTUNName(facts.InterfaceName) ||
			facts.InstanceID != utunLabInstanceID ||
			facts.OperationID != expected.requestID ||
			facts.MTU != profile.TunnelMTU ||
			!facts.HasIPv4 || !facts.HasIPv6 {
			return "", errors.New("prepare response did not prove exact utun ownership")
		}
		return facts.InterfaceName, nil
	}
	return "", errors.New("missing tunnel_prepared response")
}

func productionPreparedOutput(t *testing.T, facts ipc.TunnelDeviceFacts) []byte {
	t.Helper()
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	for _, value := range []interface{}{
		handshake{ProtocolVersion: bootstrap.ProtocolVersion, InstanceID: utunLabInstanceID, AuthProof: expectedUTUNLabAuthProof()},
		ipc.Response{ProtocolVersion: ipc.ProtocolVersion, RequestID: utunLabProfileRequestID, Result: map[string]interface{}{"Ok": map[string]interface{}{"type": "acknowledged"}}},
		ipc.Response{ProtocolVersion: ipc.ProtocolVersion, RequestID: utunLabPrepareRequestID, Result: map[string]interface{}{"Ok": map[string]interface{}{"type": "tunnel_prepared", "data": facts}}},
	} {
		if err := encoder.Encode(value); err != nil {
			t.Fatal(err)
		}
	}
	return output.Bytes()
}

func expectedUTUNLabAuthProof() string {
	config := bootstrap.Config{
		InstanceID: utunLabInstanceID,
		AuthToken:  bytes.Repeat([]byte{0x42}, 32),
	}
	proof := bootstrap.AuthProof(config)
	config.Clear()
	return proof
}

func validateUTUNLabEvidencePath(path string) (string, error) {
	if path == "" || path != filepath.Clean(path) || filepath.Dir(path) != utunLabEvidenceDirectory {
		return "", errors.New("evidence path must be a clean file directly under /var/tmp")
	}
	base := filepath.Base(path)
	if !strings.HasPrefix(base, utunLabEvidenceBasePrefix) {
		return "", errors.New("evidence path must use the fixed disposable-VM prefix")
	}
	suffix := strings.TrimPrefix(base, utunLabEvidenceBasePrefix)
	if suffix == "" || len(suffix) > 96 {
		return "", errors.New("evidence path suffix is invalid")
	}
	for _, character := range suffix {
		if character > 127 || !(character >= 'a' && character <= 'z') &&
			!(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') &&
			character != '-' && character != '_' && character != '.' {
			return "", errors.New("evidence path suffix is invalid")
		}
	}
	return path, nil
}

func writeUTUNLabControllerEvidence(path, interfaceName string, childPID int) error {
	validatedPath, err := validateUTUNLabEvidencePath(path)
	if err != nil {
		return err
	}
	encoded, err := encodeUTUNLabControllerEvidence(interfaceName, childPID)
	if err != nil {
		return err
	}
	defer clear(encoded)
	file, err := os.OpenFile(validatedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create exclusive utun evidence file: %w", err)
	}
	written, writeErr := file.Write(encoded)
	if writeErr == nil && written != len(encoded) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write utun evidence file: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close utun evidence file: %w", closeErr)
	}
	return nil
}

func encodeUTUNLabControllerEvidence(interfaceName string, childPID int) ([]byte, error) {
	if !validLabUTUNName(interfaceName) || childPID <= 1 {
		return nil, errors.New("invalid exact utun ownership evidence")
	}
	return []byte(interfaceName + "\n" + strconv.Itoa(childPID) + "\n"), nil
}

func validLabUTUNName(name string) bool {
	suffix := strings.TrimPrefix(name, "utun")
	if suffix == name || suffix == "" {
		return false
	}
	index, err := strconv.ParseUint(suffix, 10, 31)
	return err == nil && strconv.FormatUint(index, 10) == suffix
}

func replaceEnvironmentValue(environment []string, key, value string) []string {
	prefix := key + "="
	replaced := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			replaced = append(replaced, entry)
		}
	}
	return append(replaced, prefix+value)
}
