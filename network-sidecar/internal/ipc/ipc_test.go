package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

type faultBackend struct {
	fail       string
	closeCalls int
}

type cancellableBackend struct {
	faultBackend
	started  chan struct{}
	canceled chan struct{}
	once     sync.Once
}

type loopbackBlackholeBackend struct {
	faultBackend
	listener net.Listener
	signal   io.Writer
	close    sync.Once
}

func newLoopbackBlackholeBackend(signal io.Writer) (*loopbackBlackholeBackend, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &loopbackBlackholeBackend{listener: listener, signal: signal}, nil
}

func (backend *loopbackBlackholeBackend) Health(ctx context.Context) (Health, error) {
	accepted := make(chan net.Conn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, err := backend.listener.Accept()
		if err != nil {
			acceptErrors <- err
			return
		}
		accepted <- connection
	}()
	client, err := net.Dial("tcp", backend.listener.Addr().String())
	if err != nil {
		return Health{}, err
	}
	defer client.Close()
	var peer net.Conn
	select {
	case peer = <-accepted:
		defer peer.Close()
	case err := <-acceptErrors:
		return Health{}, err
	case <-ctx.Done():
		return Health{}, ctx.Err()
	}
	if _, err := fmt.Fprintln(backend.signal, "health-started"); err != nil {
		return Health{}, err
	}
	// The accepted loopback peer deliberately sends no response. Only the
	// operation context may release this health call.
	<-ctx.Done()
	return Health{}, ctx.Err()
}

func (backend *loopbackBlackholeBackend) Close() error {
	backend.close.Do(func() {
		_ = backend.listener.Close()
		backend.closeCalls++
	})
	return nil
}

func (backend *cancellableBackend) Connect(ctx context.Context, _ profile.Transport, _ profile.NormalizedEndpoint) error {
	close(backend.started)
	<-ctx.Done()
	backend.once.Do(func() { close(backend.canceled) })
	return ctx.Err()
}

func (backend *faultBackend) Prepare(_ context.Context, _ *profile.Profile, operationID string) (TunnelDeviceFacts, error) {
	if backend.fail == "prepare" {
		return TunnelDeviceFacts{}, ErrBackendUnavailable
	}
	return TunnelDeviceFacts{
		InterfaceName: "userspace",
		MTU:           profile.TunnelMTU,
		HasIPv4:       true,
		HasIPv6:       true,
		InstanceID:    "fault.instance",
		OperationID:   operationID,
	}, nil
}

func (backend *faultBackend) Connect(context.Context, profile.Transport, profile.NormalizedEndpoint) error {
	if backend.fail == "connect" {
		return ErrBackendUnavailable
	}
	return nil
}

func (backend *faultBackend) Health(context.Context) (Health, error) {
	if backend.fail == "health" {
		return Health{}, ErrBackendUnavailable
	}
	return Health{Reachable: true, LatencyMS: 12, JitterMS: 3, LossPercent: 1}, nil
}

func (backend *faultBackend) Disconnect(context.Context) error {
	if backend.fail == "disconnect" {
		return ErrBackendUnavailable
	}
	return nil
}

func (backend *faultBackend) Stop(context.Context) error {
	if backend.fail == "stop" {
		return ErrBackendUnavailable
	}
	return nil
}

func (backend *faultBackend) Close() error {
	backend.closeCalls++
	return nil
}

func TestServeMatchesRustStatusAndDisconnectWireFormat(t *testing.T) {
	input := strings.Join([]string{
		`{"protocol_version":2,"request_id":"request.status","payload":{"type":"get_status"}}`,
		`{"protocol_version":2,"request_id":"request.stop","payload":{"type":"disconnect"}}`,
		"",
	}, "\n")
	var output bytes.Buffer
	inputStream := io.NopCloser(strings.NewReader(input))
	if err := Serve(bufio.NewReader(inputStream), inputStream, &output); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("expected two responses, got %q", output.String())
	}
	var status map[string]interface{}
	if err := json.Unmarshal(lines[0], &status); err != nil {
		t.Fatal(err)
	}
	result := status["result"].(map[string]interface{})["Ok"].(map[string]interface{})
	if result["type"] != "status" || result["data"].(map[string]interface{})["state"] != "disconnected" {
		t.Fatalf("unexpected status response: %s", lines[0])
	}
	fixture, err := os.ReadFile("../../../schemas/fixtures/network-ipc-v2.status.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtureValue interface{}
	var responseValue interface{}
	if err := json.Unmarshal(fixture, &fixtureValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[0], &responseValue); err != nil {
		t.Fatal(err)
	}
	if !deepEqualJSON(responseValue, fixtureValue) {
		t.Fatalf("Go status response diverged from shared fixture: %s", lines[0])
	}
	var stopped map[string]interface{}
	if err := json.Unmarshal(lines[1], &stopped); err != nil {
		t.Fatal(err)
	}
	stopResult := stopped["result"].(map[string]interface{})["Ok"].(map[string]interface{})
	if stopResult["type"] != "acknowledged" {
		t.Fatalf("unexpected stop response: %s", lines[1])
	}
}

func deepEqualJSON(left, right interface{}) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func TestSessionEnforcesExplicitBreakBeforeMakeLifecycle(t *testing.T) {
	profileData, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	current := newSession()
	requests := []Request{
		{ProtocolVersion: ProtocolVersion, RequestID: "request.profile", Payload: Payload{Type: "apply_profile", Data: profileData}},
		{ProtocolVersion: ProtocolVersion, RequestID: "request.prepare", Payload: Payload{Type: "prepare_tunnel"}},
		{ProtocolVersion: ProtocolVersion, RequestID: "request.quic", Payload: Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"quic"}`)}},
		{ProtocolVersion: ProtocolVersion, RequestID: "request.health", Payload: Payload{Type: "sample_health"}},
		{ProtocolVersion: ProtocolVersion, RequestID: "request.close_quic", Payload: Payload{Type: "disconnect_transport"}},
		{ProtocolVersion: ProtocolVersion, RequestID: "request.wss", Payload: Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"wss"}`)}},
		{ProtocolVersion: ProtocolVersion, RequestID: "request.close_wss", Payload: Payload{Type: "disconnect_transport"}},
		{ProtocolVersion: ProtocolVersion, RequestID: "request.stop", Payload: Payload{Type: "stop_tunnel"}},
	}
	for _, request := range requests {
		response, stop := current.handle(request)
		if stop || response.Result["Err"] != nil {
			t.Fatalf("request %s failed: %#v", request.Payload.Type, response)
		}
		if request.Payload.Type == "prepare_tunnel" {
			prepared := response.Result["Ok"].(map[string]interface{})
			facts := prepared["data"].(TunnelDeviceFacts)
			if prepared["type"] != "tunnel_prepared" || facts.InstanceID != "contract.instance" || facts.OperationID != request.RequestID || facts.MTU != profile.TunnelMTU {
				t.Fatalf("prepare response lost exact tunnel ownership: %#v", prepared)
			}
		}
	}
	if status := current.status(); status.State != "disconnected" || status.ActiveProfileID == nil || status.ActiveTransport != nil {
		t.Fatalf("unexpected final status: %#v", status)
	}
}

func TestSessionRejectsMakeBeforeBreakAndInvalidOrdering(t *testing.T) {
	profileData, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	current := newSession()
	assertInvalidState := func(request Request) {
		t.Helper()
		response, stop := current.handle(request)
		failure, ok := response.Result["Err"].(Error)
		if stop || !ok || failure.Code != "invalid_state_transition" {
			t.Fatalf("expected invalid state, got %#v", response)
		}
	}
	assertInvalidState(Request{ProtocolVersion: ProtocolVersion, RequestID: "request.early", Payload: Payload{Type: "prepare_tunnel"}})
	current.handle(Request{ProtocolVersion: ProtocolVersion, RequestID: "request.profile", Payload: Payload{Type: "apply_profile", Data: profileData}})
	current.handle(Request{ProtocolVersion: ProtocolVersion, RequestID: "request.prepare", Payload: Payload{Type: "prepare_tunnel"}})
	current.handle(Request{ProtocolVersion: ProtocolVersion, RequestID: "request.quic", Payload: Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"quic"}`)}})
	assertInvalidState(Request{ProtocolVersion: ProtocolVersion, RequestID: "request.wss", Payload: Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"wss"}`)}})
}

func TestRequestValidationFailsClosed(t *testing.T) {
	for _, input := range []string{
		`{}`,
		`{"protocol_version":1,"request_id":"request.test","payload":{"type":"get_status"}}`,
		`{"protocol_version":3,"request_id":"request.test","payload":{"type":"get_status"}}`,
		`{"protocol_version":2,"request_id":"../bad","payload":{"type":"get_status"}}`,
		`{"protocol_version":2,"request_id":".request.test","payload":{"type":"get_status"}}`,
		`{"protocol_version":2,"request_id":"request.test.","payload":{"type":"get_status"}}`,
		`{"protocol_version":2,"request_id":"request..test","payload":{"type":"get_status"}}`,
		`{"protocol_version":2,"request_id":"request/path","payload":{"type":"get_status"}}`,
		`{"protocol_version":2,"request_id":"request\\path","payload":{"type":"get_status"}}`,
		`{"protocol_version":2,"request_id":"request.test","payload":{"type":"get_status"},"unknown":true}`,
	} {
		if _, err := decodeRequest(bufio.NewReader(strings.NewReader(input + "\n"))); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("expected invalid request for %q, got %v", input, err)
		}
	}
}

func TestRequestRejectsCompleteJSONWithoutLF(t *testing.T) {
	input := `{"protocol_version":2,"request_id":"request.unterminated","payload":{"type":"get_status"}}`
	if _, err := decodeRequest(bufio.NewReader(strings.NewReader(input))); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected unterminated IPC record refusal, got %v", err)
	}
}

func TestBackendFailureNeverAdvancesSessionState(t *testing.T) {
	profileData, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	backend := &faultBackend{fail: "prepare"}
	current := newSessionWithBackend(backend)
	current.handle(Request{ProtocolVersion: ProtocolVersion, RequestID: "request.profile", Payload: Payload{Type: "apply_profile", Data: profileData}})
	response, _ := current.handle(Request{ProtocolVersion: ProtocolVersion, RequestID: "request.prepare", Payload: Payload{Type: "prepare_tunnel"}})
	if current.tunnelPrepared || response.Result["Err"].(Error).Code != "sidecar_unavailable" {
		t.Fatalf("prepare failure advanced state: %#v", current.status())
	}

	backend.fail = ""
	current.handle(Request{ProtocolVersion: ProtocolVersion, RequestID: "request.prepare_ok", Payload: Payload{Type: "prepare_tunnel"}})
	backend.fail = "connect"
	response, _ = current.handle(Request{ProtocolVersion: ProtocolVersion, RequestID: "request.connect", Payload: Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"quic"}`)}})
	if current.activeTransport != "" || response.Result["Err"].(Error).Code != "sidecar_unavailable" {
		t.Fatalf("connect failure advanced state: %#v", current.status())
	}
}

func TestBackendFailureReasonCodeIsStableAndStateRemainsBounded(t *testing.T) {
	profileData, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}

	requestFor := func(payloadType string, data json.RawMessage) Request {
		return Request{ProtocolVersion: ProtocolVersion, RequestID: "request." + payloadType, Payload: Payload{Type: payloadType, Data: data}}
	}
	assertFailure := func(t *testing.T, current *session, request Request, before Status) {
		t.Helper()
		sameOptional := func(left, right *string) bool {
			if left == nil || right == nil {
				return left == nil && right == nil
			}
			return *left == *right
		}
		response, stop := current.handle(request)
		failure, ok := response.Result["Err"].(Error)
		if stop || !ok || failure.Code != "sidecar_unavailable" || !failure.Retryable {
			t.Fatalf("unexpected stable backend failure: stop=%v response=%#v", stop, response)
		}
		after := current.status()
		if after.State != before.State || !sameOptional(after.ActiveProfileID, before.ActiveProfileID) || !sameOptional(after.ActiveTransport, before.ActiveTransport) {
			t.Fatalf("backend failure advanced state: before=%#v after=%#v", before, after)
		}
		if after.LastError == nil || *after.LastError != "sidecar_unavailable" {
			t.Fatalf("backend failure did not retain stable status reason: %#v", after)
		}
	}

	t.Run("prepare", func(t *testing.T) {
		backend := &faultBackend{fail: "prepare"}
		current := newSessionWithBackend(backend)
		current.handle(requestFor("apply_profile", profileData))
		before := current.status()
		assertFailure(t, current, requestFor("prepare_tunnel", nil), before)
	})

	t.Run("connect", func(t *testing.T) {
		backend := &faultBackend{fail: "connect"}
		current := newSessionWithBackend(backend)
		current.handle(requestFor("apply_profile", profileData))
		current.handle(requestFor("prepare_tunnel", nil))
		before := current.status()
		assertFailure(t, current, requestFor("connect_transport", json.RawMessage(`{"transport":"quic"}`)), before)
	})

	for _, phase := range []string{"health", "disconnect", "stop"} {
		t.Run(phase, func(t *testing.T) {
			backend := &faultBackend{}
			current := newSessionWithBackend(backend)
			current.handle(requestFor("apply_profile", profileData))
			current.handle(requestFor("prepare_tunnel", nil))
			current.handle(requestFor("connect_transport", json.RawMessage(`{"transport":"quic"}`)))
			if phase == "health" {
				backend.fail = "health"
				before := current.status()
				assertFailure(t, current, requestFor("sample_health", nil), before)
				return
			}
			if phase == "disconnect" {
				backend.fail = "disconnect"
				before := current.status()
				assertFailure(t, current, requestFor("disconnect_transport", nil), before)
				return
			}
			if _, stop := current.handle(requestFor("disconnect_transport", nil)); stop {
				t.Fatal("transport disconnect unexpectedly stopped session")
			}
			backend.fail = "stop"
			before := current.status()
			assertFailure(t, current, requestFor("stop_tunnel", nil), before)
		})
	}
}

func TestHealthMatchesSharedFixture(t *testing.T) {
	current := newSessionWithBackend(&faultBackend{})
	current.tunnelPrepared = true
	current.activeTransport = profile.QUIC
	response, stop := current.handle(Request{ProtocolVersion: ProtocolVersion, RequestID: "request.health", Payload: Payload{Type: "sample_health"}})
	if stop {
		t.Fatal("health stopped session")
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../../schemas/fixtures/network-ipc-v2.health.json")
	if err != nil {
		t.Fatal(err)
	}
	var actualValue interface{}
	var fixtureValue interface{}
	if json.Unmarshal(encoded, &actualValue) != nil || json.Unmarshal(fixture, &fixtureValue) != nil || !deepEqualJSON(actualValue, fixtureValue) {
		t.Fatalf("Go health response diverged from shared fixture: %s", encoded)
	}
}

func TestEOFClosesBackend(t *testing.T) {
	backend := &faultBackend{}
	emptyInput := io.NopCloser(strings.NewReader(""))
	if err := ServeWithBackend(bufio.NewReader(emptyInput), emptyInput, &bytes.Buffer{}, backend); err != nil {
		t.Fatal(err)
	}
	if backend.closeCalls != 1 {
		t.Fatalf("expected one EOF cleanup, got %d", backend.closeCalls)
	}
}

func TestServeReadsCancelWhileConnectIsInFlight(t *testing.T) {
	profileData, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var compactProfile bytes.Buffer
	if err := json.Compact(&compactProfile, profileData); err != nil {
		t.Fatal(err)
	}
	backend := &cancellableBackend{started: make(chan struct{}), canceled: make(chan struct{})}
	inputReader, inputWriter := io.Pipe()
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- ServeWithBackend(bufio.NewReader(inputReader), inputReader, &output, backend) }()
	write := func(record string) {
		t.Helper()
		if _, err := io.WriteString(inputWriter, record+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	write(fmt.Sprintf(`{"protocol_version":2,"request_id":"request.profile","payload":{"type":"apply_profile","data":%s}}`, compactProfile.Bytes()))
	write(`{"protocol_version":2,"request_id":"request.prepare","payload":{"type":"prepare_tunnel"}}`)
	write(`{"protocol_version":2,"request_id":"request.connect","payload":{"type":"connect_transport","data":{"transport":"quic"}}}`)
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("connect did not start")
	}
	write(`{"protocol_version":2,"request_id":"cancel.request.connect","payload":{"type":"cancel","data":{"target_request_id":"request.connect"}}}`)
	select {
	case <-backend.canceled:
	case <-time.After(time.Second):
		t.Fatal("cancel was not dispatched during connect")
	}
	_ = inputWriter.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve did not close after EOF")
	}
	if backend.closeCalls != 1 {
		t.Fatalf("expected one backend close, got %d", backend.closeCalls)
	}
}

func TestServeContextCancellationJoinsConnectBeforeBackendClose(t *testing.T) {
	profileData, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var compactProfile bytes.Buffer
	if err := json.Compact(&compactProfile, profileData); err != nil {
		t.Fatal(err)
	}
	backend := &cancellableBackend{started: make(chan struct{}), canceled: make(chan struct{})}
	inputReader, inputWriter := io.Pipe()
	var output bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ServeWithBackendContext(ctx, bufio.NewReader(inputReader), inputReader, &output, backend)
	}()
	write := func(record string) {
		t.Helper()
		if _, err := io.WriteString(inputWriter, record+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	write(fmt.Sprintf(`{"protocol_version":2,"request_id":"request.profile","payload":{"type":"apply_profile","data":%s}}`, compactProfile.Bytes()))
	write(`{"protocol_version":2,"request_id":"request.prepare","payload":{"type":"prepare_tunnel"}}`)
	write(`{"protocol_version":2,"request_id":"request.connect","payload":{"type":"connect_transport","data":{"transport":"quic"}}}`)
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("connect did not start")
	}
	cancel()
	select {
	case <-backend.canceled:
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not cancel connect")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve did not join cancelled connect")
	}
	_ = inputWriter.Close()
	if backend.closeCalls != 1 {
		t.Fatalf("expected one backend close after context cancellation, got %d", backend.closeCalls)
	}
}

const blackholeChildEnvironment = "KYCLASH_IPC_BLACKHOLE_CHILD"

func TestLoopbackBlackholeIPCChild(t *testing.T) {
	if os.Getenv(blackholeChildEnvironment) != "1" {
		return
	}
	backend, err := newLoopbackBlackholeBackend(os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if err := ServeWithBackend(bufio.NewReader(os.Stdin), os.Stdin, os.Stdout, backend); err != nil {
		t.Fatal(err)
	}
}

type blackholeChild struct {
	command   *exec.Cmd
	cancel    context.CancelFunc
	input     io.WriteCloser
	requests  *json.Encoder
	responses *json.Decoder
	signals   *bufio.Reader
}

func startBlackholeChild(t *testing.T) *blackholeChild {
	t.Helper()
	childContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	command := exec.CommandContext(childContext, os.Args[0], "-test.run=^TestLoopbackBlackholeIPCChild$")
	command.Env = append(os.Environ(), blackholeChildEnvironment+"=1")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	signal, err := command.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	child := &blackholeChild{
		command:   command,
		cancel:    cancel,
		input:     input,
		requests:  json.NewEncoder(input),
		responses: json.NewDecoder(output),
		signals:   bufio.NewReader(signal),
	}
	t.Cleanup(func() {
		child.cancel()
		_ = child.input.Close()
		if child.command.ProcessState == nil {
			_ = child.command.Process.Kill()
			_ = child.command.Wait()
		}
	})
	return child
}

func (child *blackholeChild) exchange(t *testing.T, request Request) Response {
	t.Helper()
	if err := child.requests.Encode(request); err != nil {
		t.Fatal(err)
	}
	return child.read(t, request.RequestID)
}

func (child *blackholeChild) read(t *testing.T, requestID string) Response {
	t.Helper()
	var response Response
	if err := child.responses.Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.ProtocolVersion != ProtocolVersion || response.RequestID != requestID {
		t.Fatalf("unexpected correlated response: %#v", response)
	}
	return response
}

func (child *blackholeChild) send(t *testing.T, request Request) {
	t.Helper()
	if err := child.requests.Encode(request); err != nil {
		t.Fatal(err)
	}
}

func (child *blackholeChild) waitHealthStarted(t *testing.T) {
	t.Helper()
	result := make(chan string, 1)
	go func() {
		line, _ := child.signals.ReadString('\n')
		result <- line
	}()
	select {
	case line := <-result:
		if line != "health-started\n" {
			t.Fatalf("unexpected child health signal: %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("child health probe did not enter loopback blackhole")
	}
}

func (child *blackholeChild) wait(t *testing.T) {
	t.Helper()
	if err := child.input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.command.Wait(); err != nil {
		t.Fatal(err)
	}
	child.cancel()
}

func assertSuccessResponse(t *testing.T, response Response) {
	t.Helper()
	if _, ok := response.Result["Ok"]; !ok {
		t.Fatalf("expected successful IPC response: %#v", response)
	}
}

func setupConnectedBlackholeChild(t *testing.T) *blackholeChild {
	t.Helper()
	profileData, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	child := startBlackholeChild(t)
	for _, request := range []Request{
		{ProtocolVersion: ProtocolVersion, RequestID: "request.child.profile", Payload: Payload{Type: "apply_profile", Data: profileData}},
		{ProtocolVersion: ProtocolVersion, RequestID: "request.child.prepare", Payload: Payload{Type: "prepare_tunnel"}},
		{ProtocolVersion: ProtocolVersion, RequestID: "request.child.connect", Payload: Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"quic"}`)}},
	} {
		assertSuccessResponse(t, child.exchange(t, request))
	}
	return child
}

func TestRealChildCancelUnblocksBlackholedHealthAndPreservesIPC(t *testing.T) {
	child := setupConnectedBlackholeChild(t)
	child.send(t, Request{ProtocolVersion: ProtocolVersion, RequestID: "request.child.health", Payload: Payload{Type: "sample_health"}})
	child.waitHealthStarted(t)
	started := time.Now()
	cancel := Request{ProtocolVersion: ProtocolVersion, RequestID: "cancel.child.health", Payload: Payload{Type: "cancel", Data: json.RawMessage(`{"target_request_id":"request.child.health"}`)}}
	assertSuccessResponse(t, child.exchange(t, cancel))
	if _, ok := child.read(t, "request.child.health").Result["Err"]; !ok {
		t.Fatal("cancelled health did not return a correlated failure")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("real-child health cancellation exceeded bound: %v", elapsed)
	}
	assertSuccessResponse(t, child.exchange(t, Request{ProtocolVersion: ProtocolVersion, RequestID: "request.child.status", Payload: Payload{Type: "get_status"}}))
	assertSuccessResponse(t, child.exchange(t, Request{ProtocolVersion: ProtocolVersion, RequestID: "request.child.disconnect_transport", Payload: Payload{Type: "disconnect_transport"}}))
	assertSuccessResponse(t, child.exchange(t, Request{ProtocolVersion: ProtocolVersion, RequestID: "request.child.stop", Payload: Payload{Type: "stop_tunnel"}}))
	assertSuccessResponse(t, child.exchange(t, Request{ProtocolVersion: ProtocolVersion, RequestID: "request.child.disconnect", Payload: Payload{Type: "disconnect"}}))
	child.wait(t)
}
