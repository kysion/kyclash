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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

var errInjectedWriter = errors.New("injected IPC writer failure")

type framedResponseWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	notify chan struct{}
	fail   atomic.Bool
}

type blockingReadCloser struct {
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newBlockingReadCloser() *blockingReadCloser {
	return &blockingReadCloser{entered: make(chan struct{}), closed: make(chan struct{})}
}

func (reader *blockingReadCloser) Read([]byte) (int, error) {
	reader.once.Do(func() { close(reader.entered) })
	<-reader.closed
	return 0, net.ErrClosed
}

func (reader *blockingReadCloser) Close() error {
	select {
	case <-reader.closed:
	default:
		close(reader.closed)
	}
	return nil
}

func newFramedResponseWriter() *framedResponseWriter {
	return &framedResponseWriter{notify: make(chan struct{}, 1)}
}

func (writer *framedResponseWriter) Write(data []byte) (int, error) {
	if writer.fail.Load() {
		return 0, errInjectedWriter
	}
	writer.mu.Lock()
	count, err := writer.buffer.Write(data)
	writer.mu.Unlock()
	select {
	case writer.notify <- struct{}{}:
	default:
	}
	return count, err
}

func (writer *framedResponseWriter) next(timeout time.Duration) (Response, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		writer.mu.Lock()
		data := writer.buffer.Bytes()
		newline := bytes.IndexByte(data, '\n')
		if newline >= 0 {
			record := append([]byte(nil), data[:newline]...)
			writer.buffer.Next(newline + 1)
			writer.mu.Unlock()
			var response Response
			if err := json.Unmarshal(record, &response); err != nil {
				return Response{}, err
			}
			return response, nil
		}
		writer.mu.Unlock()
		select {
		case <-writer.notify:
		case <-timer.C:
			return Response{}, context.DeadlineExceeded
		}
	}
}

type controlHarness struct {
	input     *io.PipeWriter
	requests  *json.Encoder
	responses *framedResponseWriter
	cancel    context.CancelFunc
	done      chan struct{}
	mu        sync.Mutex
	err       error
}

func startControlHarness(t *testing.T, parent context.Context, backend Backend) *controlHarness {
	t.Helper()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	inputReader, inputWriter := io.Pipe()
	responses := newFramedResponseWriter()
	harness := &controlHarness{
		input:     inputWriter,
		requests:  json.NewEncoder(inputWriter),
		responses: responses,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	go func() {
		err := ServeWithBackendContext(ctx, bufio.NewReader(inputReader), inputReader, responses, backend)
		harness.mu.Lock()
		harness.err = err
		harness.mu.Unlock()
		close(harness.done)
	}()
	t.Cleanup(func() {
		harness.cancel()
		_ = harness.input.Close()
		select {
		case <-harness.done:
		case <-time.After(3 * time.Second):
		}
	})
	return harness
}

func (harness *controlHarness) send(request Request) error {
	return harness.requests.Encode(request)
}

func (harness *controlHarness) raw(record string) error {
	_, err := io.WriteString(harness.input, record)
	return err
}

func (harness *controlHarness) next(t *testing.T) Response {
	t.Helper()
	response, err := harness.responses.next(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func (harness *controlHarness) wait(timeout time.Duration) error {
	select {
	case <-harness.done:
		harness.mu.Lock()
		defer harness.mu.Unlock()
		return harness.err
	case <-time.After(timeout):
		return context.DeadlineExceeded
	}
}

type controlBackend struct {
	prepareCalls    atomic.Int32
	connectCalls    atomic.Int32
	healthCalls     atomic.Int32
	disconnectCalls atomic.Int32
	stopCalls       atomic.Int32
	closeCalls      atomic.Int32
	connectFn       func(context.Context, profile.Transport, profile.NormalizedEndpoint) error
	healthFn        func(context.Context) (Health, error)
	disconnectFn    func(context.Context) error
	stopFn          func(context.Context) error
	closeFn         func() error
}

type privateProbeBackend struct {
	*controlBackend
	privateCalls atomic.Int32
	privateFn    func(context.Context) (PrivateReachability, error)
}

func (backend *privateProbeBackend) PrivateReachability(ctx context.Context) (PrivateReachability, error) {
	backend.privateCalls.Add(1)
	if backend.privateFn != nil {
		return backend.privateFn(ctx)
	}
	return PrivateReachability{Reachable: true, LatencyMS: 7}, nil
}

func (backend *controlBackend) Prepare(_ context.Context, _ *profile.Profile, operationID string) (TunnelDeviceFacts, error) {
	backend.prepareCalls.Add(1)
	return TunnelDeviceFacts{
		InterfaceName: "userspace",
		MTU:           profile.TunnelMTU,
		HasIPv4:       true,
		HasIPv6:       true,
		InstanceID:    "control.instance",
		OperationID:   operationID,
	}, nil
}

func (backend *controlBackend) Connect(ctx context.Context, transport profile.Transport, endpoint profile.NormalizedEndpoint) error {
	backend.connectCalls.Add(1)
	if backend.connectFn != nil {
		return backend.connectFn(ctx, transport, endpoint)
	}
	return nil
}

func (backend *controlBackend) Health(ctx context.Context) (Health, error) {
	backend.healthCalls.Add(1)
	if backend.healthFn != nil {
		return backend.healthFn(ctx)
	}
	return Health{Reachable: true, LatencyMS: 12, JitterMS: 3, LossPercent: 1}, nil
}

func (backend *controlBackend) Disconnect(ctx context.Context) error {
	backend.disconnectCalls.Add(1)
	if backend.disconnectFn != nil {
		return backend.disconnectFn(ctx)
	}
	return nil
}

func (backend *controlBackend) Stop(ctx context.Context) error {
	backend.stopCalls.Add(1)
	if backend.stopFn != nil {
		return backend.stopFn(ctx)
	}
	return nil
}

func (backend *controlBackend) Close() error {
	backend.closeCalls.Add(1)
	if backend.closeFn != nil {
		return backend.closeFn()
	}
	return nil
}

func request(payloadType, requestID string, data json.RawMessage) Request {
	return Request{ProtocolVersion: ProtocolVersion, RequestID: requestID, Payload: Payload{Type: payloadType, Data: data}}
}

func setupPreparedHarness(t *testing.T, backend Backend) *controlHarness {
	t.Helper()
	return setupPreparedHarnessContext(t, context.Background(), backend)
}

func setupPreparedHarnessContext(t *testing.T, parent context.Context, backend Backend) *controlHarness {
	t.Helper()
	profileData, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	harness := startControlHarness(t, parent, backend)
	for _, value := range []Request{
		request("apply_profile", "request.setup.profile", profileData),
		request("prepare_tunnel", "request.setup.prepare", nil),
	} {
		if err := harness.send(value); err != nil {
			t.Fatal(err)
		}
		assertOKType(t, harness.next(t), value.RequestID, "")
	}
	return harness
}

func setupConnectedHarness(t *testing.T, backend Backend) *controlHarness {
	t.Helper()
	harness := setupPreparedHarness(t, backend)
	connect := request("connect_transport", "request.setup.connect", json.RawMessage(`{"transport":"quic"}`))
	if err := harness.send(connect); err != nil {
		t.Fatal(err)
	}
	assertOKType(t, harness.next(t), connect.RequestID, "status")
	return harness
}

func TestPrivateReachabilityIsTypedCancellableAndLabOnly(t *testing.T) {
	labBackend := &privateProbeBackend{controlBackend: &controlBackend{}}
	harness := setupConnectedHarness(t, labBackend)
	probe := request("sample_private_reachability", "request.private.echo", nil)
	if err := harness.send(probe); err != nil {
		t.Fatal(err)
	}
	assertOKType(t, harness.next(t), probe.RequestID, "private_reachability")
	if labBackend.privateCalls.Load() != 1 {
		t.Fatalf("private probe calls = %d, want 1", labBackend.privateCalls.Load())
	}
	productionBackend := &controlBackend{}
	productionHarness := setupConnectedHarness(t, productionBackend)
	rejected := request("sample_private_reachability", "request.private.production", nil)
	if err := productionHarness.send(rejected); err != nil {
		t.Fatal(err)
	}
	assertFailureCode(t, productionHarness.next(t), rejected.RequestID, "invalid_state_transition", "invalid sidecar state transition")
}

func TestPrivateReachabilityCancellationTargetsOnlyTheActiveProbe(t *testing.T) {
	started := make(chan struct{})
	backend := &privateProbeBackend{
		controlBackend: &controlBackend{},
		privateFn: func(ctx context.Context) (PrivateReachability, error) {
			close(started)
			<-ctx.Done()
			return PrivateReachability{}, ctx.Err()
		},
	}
	harness := setupConnectedHarness(t, backend)
	primary := request("sample_private_reachability", "request.private.cancelled", nil)
	if err := harness.send(primary); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("private reachability probe did not start")
	}
	cancel := request("cancel", "request.private.cancel.control", json.RawMessage(`{"target_request_id":"request.private.cancelled"}`))
	if err := harness.send(cancel); err != nil {
		t.Fatal(err)
	}
	first, second := harness.next(t), harness.next(t)
	responses := []Response{first, second}
	var accepted, cancelled bool
	for _, response := range responses {
		if response.RequestID == cancel.RequestID {
			accepted = responseOKType(response) == "cancel_accepted"
		}
		if response.RequestID == primary.RequestID {
			cancelled = responseErrorCode(response) == "operation_cancelled"
		}
	}
	if !accepted || !cancelled {
		t.Fatalf("unexpected cancellation pair: %#v %#v", first, second)
	}
}

func assertOKType(t *testing.T, response Response, requestID, expectedType string) {
	t.Helper()
	if response.ProtocolVersion != ProtocolVersion || response.RequestID != requestID {
		t.Fatalf("unexpected correlated response: %#v", response)
	}
	encoded, err := json.Marshal(response.Result["Ok"])
	if err != nil || string(encoded) == "null" {
		t.Fatalf("expected success response: %#v", response)
	}
	if expectedType == "" {
		return
	}
	var payload struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(encoded, &payload) != nil || payload.Type != expectedType {
		t.Fatalf("expected Ok type %q, got %#v", expectedType, response)
	}
}

func assertFailureCode(t *testing.T, response Response, requestID, code, message string) {
	t.Helper()
	if response.ProtocolVersion != ProtocolVersion || response.RequestID != requestID {
		t.Fatalf("unexpected correlated response: %#v", response)
	}
	encoded, err := json.Marshal(response.Result["Err"])
	if err != nil {
		t.Fatal(err)
	}
	var failure Error
	if json.Unmarshal(encoded, &failure) != nil || failure.Code != code || failure.Message != message || failure.Retryable {
		t.Fatalf("unexpected typed failure: %#v", response)
	}
}

func assertJSONFixture(t *testing.T, actual interface{}, fixturePath string) {
	t.Helper()
	fixture, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	actualJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	var actualValue interface{}
	var fixtureValue interface{}
	if json.Unmarshal(actualJSON, &actualValue) != nil || json.Unmarshal(fixture, &fixtureValue) != nil || !deepEqualJSON(actualValue, fixtureValue) {
		t.Fatalf("value diverged from %s: %s", fixturePath, actualJSON)
	}
}

func TestCancelV2FixturesMatchGoContract(t *testing.T) {
	var cancelRequest Request
	cancelFixture, err := os.ReadFile("../../../schemas/fixtures/network-ipc-v2.cancel.json")
	if err != nil || json.Unmarshal(cancelFixture, &cancelRequest) != nil {
		t.Fatal(err)
	}
	target, valid := decodeCancelTarget(cancelRequest)
	if !valid || target != "request.health.123" {
		t.Fatalf("shared cancel target was not preserved: %q %v", target, valid)
	}
	assertJSONFixture(t, cancelAccepted(cancelRequest.RequestID, target), "../../../schemas/fixtures/network-ipc-v2.cancel-accepted.json")

	var cancelWins struct {
		PrimaryResponse Response `json:"primary_response"`
		CancelResponse  Response `json:"cancel_response"`
	}
	fixture, err := os.ReadFile("../../../schemas/fixtures/network-ipc-v2.cancel-wins.json")
	if err != nil || json.Unmarshal(fixture, &cancelWins) != nil {
		t.Fatal(err)
	}
	primary := Response{ProtocolVersion: ProtocolVersion, RequestID: "request.health.123", Result: failure("operation_cancelled", "operation cancelled", false)}
	if !deepEqualJSON(primary, cancelWins.PrimaryResponse) {
		t.Fatalf("Go operation-cancelled response diverged from shared fixture: %#v", primary)
	}
	assertJSONFixture(t, cancelWins.CancelResponse, "../../../schemas/fixtures/network-ipc-v2.cancel-accepted.json")
}

func TestServeRejectsHistoricalV1BeforeOperationalBackendCall(t *testing.T) {
	backend := &controlBackend{}
	harness := startControlHarness(t, context.Background(), backend)
	if err := harness.raw(`{"protocol_version":1,"request_id":"request.v1.status","payload":{"type":"get_status"}}` + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := harness.wait(time.Second); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected v1 fail-closed error, got %v", err)
	}
	if backend.prepareCalls.Load()+backend.connectCalls.Load()+backend.healthCalls.Load()+backend.disconnectCalls.Load()+backend.stopCalls.Load() != 0 {
		t.Fatal("historical v1 request reached an operational backend method")
	}
}

func TestConnectCancellationPreservesPreparedStateAndAllowsFallbacks(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	backend := &controlBackend{}
	backend.connectFn = func(ctx context.Context, _ profile.Transport, _ profile.NormalizedEndpoint) error {
		if backend.connectCalls.Load() == 1 {
			once.Do(func() { close(started) })
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	harness := setupPreparedHarness(t, backend)
	primary := request("connect_transport", "request.connect.cancel", json.RawMessage(`{"transport":"quic"}`))
	if err := harness.send(primary); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("connect did not start")
	}
	cancel := request("cancel", "cancel.connect.request", json.RawMessage(`{"target_request_id":"request.connect.cancel"}`))
	if err := harness.send(cancel); err != nil {
		t.Fatal(err)
	}
	assertOKType(t, harness.next(t), cancel.RequestID, "cancel_accepted")
	assertFailureCode(t, harness.next(t), primary.RequestID, "operation_cancelled", "operation cancelled")

	status := request("get_status", "request.connect.cancel.status", nil)
	if err := harness.send(status); err != nil {
		t.Fatal(err)
	}
	statusResponse := harness.next(t)
	assertOKType(t, statusResponse, status.RequestID, "status")
	statusJSON, _ := json.Marshal(statusResponse.Result["Ok"])
	if !bytes.Contains(statusJSON, []byte(`"state":"preparing_tunnel"`)) || !bytes.Contains(statusJSON, []byte(`"last_error":null`)) {
		t.Fatalf("cancelled connect corrupted prepared state: %s", statusJSON)
	}

	for index, transport := range []string{"wss", "tcp"} {
		connect := request("connect_transport", fmt.Sprintf("request.fallback.%d", index), json.RawMessage(`{"transport":"`+transport+`"}`))
		if err := harness.send(connect); err != nil {
			t.Fatal(err)
		}
		assertOKType(t, harness.next(t), connect.RequestID, "status")
		disconnect := request("disconnect_transport", fmt.Sprintf("request.fallback.disconnect.%d", index), nil)
		if err := harness.send(disconnect); err != nil {
			t.Fatal(err)
		}
		assertOKType(t, harness.next(t), disconnect.RequestID, "status")
	}
}

func TestHealthCancellationPreservesCarrierAndContinuesIPC(t *testing.T) {
	started := make(chan struct{})
	backend := &controlBackend{}
	backend.healthFn = func(ctx context.Context) (Health, error) {
		if backend.healthCalls.Load() == 1 {
			close(started)
			<-ctx.Done()
			return Health{}, ctx.Err()
		}
		return Health{Reachable: true, LatencyMS: 12, JitterMS: 3, LossPercent: 1}, nil
	}
	harness := setupConnectedHarness(t, backend)
	primary := request("sample_health", "request.health.123", nil)
	if err := harness.send(primary); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("health did not start")
	}
	cancel := request("cancel", "cancel.0000000000000001", json.RawMessage(`{"target_request_id":"request.health.123"}`))
	if err := harness.send(cancel); err != nil {
		t.Fatal(err)
	}
	cancelResponse := harness.next(t)
	primaryResponse := harness.next(t)
	assertJSONFixture(t, cancelResponse, "../../../schemas/fixtures/network-ipc-v2.cancel-accepted.json")
	var cancelWins struct {
		PrimaryResponse Response `json:"primary_response"`
	}
	fixture, err := os.ReadFile("../../../schemas/fixtures/network-ipc-v2.cancel-wins.json")
	if err != nil || json.Unmarshal(fixture, &cancelWins) != nil {
		t.Fatal(err)
	}
	if !deepEqualJSON(primaryResponse, cancelWins.PrimaryResponse) {
		t.Fatalf("cancelled health diverged from shared fixture: %#v", primaryResponse)
	}

	status := request("get_status", "request.health.cancel.status", nil)
	if err := harness.send(status); err != nil {
		t.Fatal(err)
	}
	statusResponse := harness.next(t)
	statusJSON, _ := json.Marshal(statusResponse.Result["Ok"])
	if !bytes.Contains(statusJSON, []byte(`"state":"connected_primary"`)) || !bytes.Contains(statusJSON, []byte(`"active_transport":"quic"`)) || !bytes.Contains(statusJSON, []byte(`"last_error":null`)) {
		t.Fatalf("cancelled health corrupted active carrier state: %s", statusJSON)
	}

	health := request("sample_health", "request.health.continued", nil)
	if err := harness.send(health); err != nil {
		t.Fatal(err)
	}
	assertOKType(t, harness.next(t), health.RequestID, "health")
	disconnect := request("disconnect_transport", "request.health.disconnect", nil)
	if err := harness.send(disconnect); err != nil {
		t.Fatal(err)
	}
	assertOKType(t, harness.next(t), disconnect.RequestID, "status")
}

func TestCompletionWinsReturnsAuthoritativePrimaryAndTooLateCancel(t *testing.T) {
	backend := &controlBackend{}
	harness := setupConnectedHarness(t, backend)
	primary := request("sample_health", "request.health.123", nil)
	if err := harness.send(primary); err != nil {
		t.Fatal(err)
	}
	primaryResponse := harness.next(t)
	cancel := request("cancel", "cancel.0000000000000001", json.RawMessage(`{"target_request_id":"request.health.123"}`))
	if err := harness.send(cancel); err != nil {
		t.Fatal(err)
	}
	cancelResponse := harness.next(t)
	var fixture struct {
		PrimaryResponse Response `json:"primary_response"`
		CancelResponse  Response `json:"cancel_response"`
	}
	data, err := os.ReadFile("../../../schemas/fixtures/network-ipc-v2.completion-wins.json")
	if err != nil || json.Unmarshal(data, &fixture) != nil {
		t.Fatal(err)
	}
	if !deepEqualJSON(primaryResponse, fixture.PrimaryResponse) || !deepEqualJSON(cancelResponse, fixture.CancelResponse) {
		t.Fatalf("completion-wins responses diverged: primary=%#v cancel=%#v", primaryResponse, cancelResponse)
	}
}

func TestCancelCompletionRaceNeverAcceptsCancelWithPrimarySuccess(t *testing.T) {
	type healthCall struct {
		release chan struct{}
	}
	calls := make(chan healthCall, 64)
	backend := &controlBackend{}
	backend.healthFn = func(context.Context) (Health, error) {
		call := healthCall{release: make(chan struct{})}
		calls <- call
		<-call.release
		return Health{Reachable: true, LatencyMS: 12, JitterMS: 3, LossPercent: 1}, nil
	}
	harness := setupConnectedHarness(t, backend)
	for index := 0; index < 48; index++ {
		primaryID := fmt.Sprintf("request.race.health.%d", index)
		cancelID := fmt.Sprintf("cancel.race.health.%d", index)
		if err := harness.send(request("sample_health", primaryID, nil)); err != nil {
			t.Fatal(err)
		}
		call := <-calls
		sendDone := make(chan error, 1)
		go func() {
			sendDone <- harness.send(request("cancel", cancelID, json.RawMessage(`{"target_request_id":"`+primaryID+`"}`)))
		}()
		close(call.release)
		if err := <-sendDone; err != nil {
			t.Fatal(err)
		}
		first := harness.next(t)
		second := harness.next(t)
		responses := map[string]Response{first.RequestID: first, second.RequestID: second}
		primaryResponse, primaryOK := responses[primaryID]
		cancelResponse, cancelOK := responses[cancelID]
		if !primaryOK || !cancelOK {
			t.Fatalf("race lost exact response IDs: %#v %#v", first, second)
		}
		primaryError := responseErrorCode(primaryResponse)
		cancelError := responseErrorCode(cancelResponse)
		cancelType := responseOKType(cancelResponse)
		switch {
		case primaryError == "operation_cancelled" && cancelType == "cancel_accepted":
		case responseOKType(primaryResponse) == "health" && cancelError == "invalid_state_transition":
		default:
			t.Fatalf("forbidden cancel/completion outcome: primary=%#v cancel=%#v", primaryResponse, cancelResponse)
		}
	}
}

func responseErrorCode(response Response) string {
	encoded, _ := json.Marshal(response.Result["Err"])
	var failure Error
	_ = json.Unmarshal(encoded, &failure)
	return failure.Code
}

func responseOKType(response Response) string {
	encoded, _ := json.Marshal(response.Result["Ok"])
	var payload struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(encoded, &payload)
	return payload.Type
}

func TestCancelPayloadValidationRejectsSameIDUnknownAndMissingTargets(t *testing.T) {
	for name, value := range map[string]Request{
		"same id":        request("cancel", "request.cancel.same", json.RawMessage(`{"target_request_id":"request.cancel.same"}`)),
		"unknown field":  request("cancel", "request.cancel.unknown", json.RawMessage(`{"target_request_id":"request.target.valid","unknown":true}`)),
		"missing target": request("cancel", "request.cancel.missing", json.RawMessage(`{}`)),
		"invalid target": request("cancel", "request.cancel.invalid", json.RawMessage(`{"target_request_id":"bad"}`)),
	} {
		t.Run(name, func(t *testing.T) {
			if target, valid := decodeCancelTarget(value); valid || target != "" {
				t.Fatalf("invalid cancel payload was accepted: %#v", value)
			}
		})
	}
}

func TestIdleCancelIsTypedTooLateWithoutBackendCancel(t *testing.T) {
	backend := &controlBackend{}
	harness := startControlHarness(t, context.Background(), backend)
	cancel := request("cancel", "cancel.idle.request", json.RawMessage(`{"target_request_id":"request.stale.target"}`))
	if err := harness.send(cancel); err != nil {
		t.Fatal(err)
	}
	assertFailureCode(t, harness.next(t), cancel.RequestID, "invalid_state_transition", "operation already completed")
}

func TestRequestVersionAndControlTypesRemainV2Only(t *testing.T) {
	if ProtocolVersion != 2 {
		t.Fatalf("unexpected IPC protocol version: %d", ProtocolVersion)
	}
	for _, response := range []Response{
		cancelAccepted("cancel.version.test", "request.version.target"),
		cancelTooLate("cancel.version.late"),
	} {
		if response.ProtocolVersion != 2 {
			t.Fatalf("control response escaped v2: %#v", response)
		}
	}
	if strings.Contains(fmt.Sprintf("%#v", cancelAccepted("cancel.version.test", "request.version.target")), "acknowledged") {
		t.Fatal("typed cancellation regressed to a generic acknowledgement")
	}
}

func TestActiveOperationRejectsEveryNonExactControlFrame(t *testing.T) {
	cases := map[string]string{
		"mismatched target":       `{"protocol_version":2,"request_id":"cancel.violation.mismatch","payload":{"type":"cancel","data":{"target_request_id":"request.somewhere.else"}}}` + "\n",
		"same request and target": `{"protocol_version":2,"request_id":"request.violation.health","payload":{"type":"cancel","data":{"target_request_id":"request.violation.health"}}}` + "\n",
		"cancel unknown data":     `{"protocol_version":2,"request_id":"cancel.violation.unknown","payload":{"type":"cancel","data":{"target_request_id":"request.violation.health","unknown":true}}}` + "\n",
		"status":                  `{"protocol_version":2,"request_id":"request.violation.status","payload":{"type":"get_status"}}` + "\n",
		"disconnect":              `{"protocol_version":2,"request_id":"request.violation.disconnect","payload":{"type":"disconnect"}}` + "\n",
		"disconnect transport":    `{"protocol_version":2,"request_id":"request.violation.disconnect.transport","payload":{"type":"disconnect_transport"}}` + "\n",
		"second health":           `{"protocol_version":2,"request_id":"request.violation.health.second","payload":{"type":"sample_health"}}` + "\n",
		"second connect":          `{"protocol_version":2,"request_id":"request.violation.connect","payload":{"type":"connect_transport","data":{"transport":"wss"}}}` + "\n",
		"unknown primary":         `{"protocol_version":2,"request_id":"request.violation.unknown","payload":{"type":"unknown_request"}}` + "\n",
		"wrong version":           `{"protocol_version":1,"request_id":"cancel.violation.version","payload":{"type":"cancel","data":{"target_request_id":"request.violation.health"}}}` + "\n",
		"unknown top level":       `{"protocol_version":2,"request_id":"cancel.violation.outer","payload":{"type":"cancel","data":{"target_request_id":"request.violation.health"}},"unknown":true}` + "\n",
		"unknown payload":         `{"protocol_version":2,"request_id":"cancel.violation.payload","payload":{"type":"cancel","data":{"target_request_id":"request.violation.health"},"unknown":true}}` + "\n",
		"malformed":               `{"protocol_version":2,"request_id":` + "\n",
	}
	for name, record := range cases {
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{})
			var startOnce sync.Once
			backend := &controlBackend{}
			backend.healthFn = func(ctx context.Context) (Health, error) {
				startOnce.Do(func() { close(started) })
				<-ctx.Done()
				return Health{}, ctx.Err()
			}
			harness := setupConnectedHarness(t, backend)
			primary := request("sample_health", "request.violation.health", nil)
			if err := harness.send(primary); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("health operation did not start")
			}
			if err := harness.raw(record); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
			if err := harness.wait(lifecycleJoinTimeout + time.Second); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected fail-stop protocol violation, got %v", err)
			}
			if backend.closeCalls.Load() != 1 {
				t.Fatalf("protocol violation did not close backend exactly once: %d", backend.closeCalls.Load())
			}
		})
	}
}

func TestCancellingStateRejectsDuplicateCancelAndThirdFrame(t *testing.T) {
	for name, record := range map[string]string{
		"duplicate cancel": `{"protocol_version":2,"request_id":"cancel.duplicate.second","payload":{"type":"cancel","data":{"target_request_id":"request.cancelling.health"}}}` + "\n",
		"third frame":      `{"protocol_version":2,"request_id":"request.cancelling.status","payload":{"type":"get_status"}}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			backend := &controlBackend{}
			backend.healthFn = func(context.Context) (Health, error) {
				close(started)
				<-release
				return Health{Reachable: true}, nil
			}
			backend.closeFn = func() error {
				releaseOnce.Do(func() { close(release) })
				return nil
			}
			harness := setupConnectedHarness(t, backend)
			primary := request("sample_health", "request.cancelling.health", nil)
			if err := harness.send(primary); err != nil {
				t.Fatal(err)
			}
			<-started
			cancel := request("cancel", "cancel.cancelling.first", json.RawMessage(`{"target_request_id":"request.cancelling.health"}`))
			if err := harness.send(cancel); err != nil {
				t.Fatal(err)
			}
			assertOKType(t, harness.next(t), cancel.RequestID, "cancel_accepted")
			if err := harness.raw(record); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
			if err := harness.wait(lifecycleJoinTimeout + time.Second); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected cancelling-state fail-stop, got %v", err)
			}
		})
	}
}

func TestActiveOperationRejectsTruncatedAndOversizedRecords(t *testing.T) {
	cases := []struct {
		name       string
		record     string
		closeInput bool
		asyncWrite bool
	}{
		{name: "truncated", record: `{"protocol_version":2,"request_id":"cancel.truncated"`, closeInput: true},
		{name: "oversized", record: strings.Repeat("x", maxRequestSize+1) + "\n", asyncWrite: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			started := make(chan struct{})
			backend := &controlBackend{}
			backend.healthFn = func(ctx context.Context) (Health, error) {
				close(started)
				<-ctx.Done()
				return Health{}, ctx.Err()
			}
			harness := setupConnectedHarness(t, backend)
			if err := harness.send(request("sample_health", "request.record.health", nil)); err != nil {
				t.Fatal(err)
			}
			<-started
			writeDone := make(chan error, 1)
			if test.asyncWrite {
				go func() { writeDone <- harness.raw(test.record) }()
			} else {
				writeDone <- harness.raw(test.record)
			}
			if test.closeInput {
				_ = harness.input.Close()
			}
			if err := harness.wait(time.Second); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected %s record to fail closed, got %v", test.name, err)
			}
			_ = harness.input.Close()
			select {
			case err := <-writeDone:
				if err != nil && !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("record writer did not unblock after fail-stop close")
			}
		})
	}
}

func TestCancelledSuccessfulConnectIsRolledBackBeforeResponse(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	backend := &controlBackend{}
	backend.connectFn = func(context.Context, profile.Transport, profile.NormalizedEndpoint) error {
		close(started)
		<-release
		return nil
	}
	harness := setupPreparedHarness(t, backend)
	primary := request("connect_transport", "request.connect.success.race", json.RawMessage(`{"transport":"quic"}`))
	if err := harness.send(primary); err != nil {
		t.Fatal(err)
	}
	<-started
	cancel := request("cancel", "cancel.connect.success.race", json.RawMessage(`{"target_request_id":"request.connect.success.race"}`))
	if err := harness.send(cancel); err != nil {
		t.Fatal(err)
	}
	assertOKType(t, harness.next(t), cancel.RequestID, "cancel_accepted")
	close(release)
	assertFailureCode(t, harness.next(t), primary.RequestID, "operation_cancelled", "operation cancelled")
	if backend.disconnectCalls.Load() != 1 {
		t.Fatalf("successful connect that lost cancellation race was not rolled back: %d", backend.disconnectCalls.Load())
	}
	status := request("get_status", "request.connect.success.status", nil)
	if err := harness.send(status); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(harness.next(t).Result["Ok"])
	if !bytes.Contains(encoded, []byte(`"state":"preparing_tunnel"`)) || !bytes.Contains(encoded, []byte(`"active_transport":null`)) {
		t.Fatalf("cancelled successful connect remained active: %s", encoded)
	}
}

func TestCancelledConnectRollbackFailureDoesNotJoinCompletedOperationTwice(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	injected := errors.New("injected cancel rollback failure")
	backend := &controlBackend{}
	backend.connectFn = func(context.Context, profile.Transport, profile.NormalizedEndpoint) error {
		close(started)
		<-release
		return nil
	}
	backend.disconnectFn = func(context.Context) error { return injected }
	harness := setupPreparedHarness(t, backend)
	primary := request("connect_transport", "request.connect.rollback.failure", json.RawMessage(`{"transport":"quic"}`))
	if err := harness.send(primary); err != nil {
		t.Fatal(err)
	}
	<-started
	cancel := request("cancel", "cancel.connect.rollback.failure", json.RawMessage(`{"target_request_id":"request.connect.rollback.failure"}`))
	if err := harness.send(cancel); err != nil {
		t.Fatal(err)
	}
	assertOKType(t, harness.next(t), cancel.RequestID, "cancel_accepted")
	startedAt := time.Now()
	close(release)
	if err := harness.wait(time.Second); !errors.Is(err, injected) {
		t.Fatalf("expected exact rollback failure, got %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("completed rollback failure was joined twice: %v", elapsed)
	}
	if backend.closeCalls.Load() != 1 {
		t.Fatalf("rollback failure did not close backend exactly once: %d", backend.closeCalls.Load())
	}
}

func TestRepeatedHealthCancellationDoesNotContaminateFutureOperations(t *testing.T) {
	started := make(chan int, 8)
	backend := &controlBackend{}
	backend.healthFn = func(ctx context.Context) (Health, error) {
		call := int(backend.healthCalls.Load())
		if call <= 8 {
			started <- call
			<-ctx.Done()
			return Health{}, ctx.Err()
		}
		return Health{Reachable: true, LatencyMS: 9, JitterMS: 1}, nil
	}
	harness := setupConnectedHarness(t, backend)
	for index := 1; index <= 8; index++ {
		primaryID := fmt.Sprintf("request.repeat.health.%d", index)
		cancelID := fmt.Sprintf("cancel.repeat.health.%d", index)
		if err := harness.send(request("sample_health", primaryID, nil)); err != nil {
			t.Fatal(err)
		}
		if call := <-started; call != index {
			t.Fatalf("unexpected health call order: %d != %d", call, index)
		}
		if err := harness.send(request("cancel", cancelID, json.RawMessage(`{"target_request_id":"`+primaryID+`"}`))); err != nil {
			t.Fatal(err)
		}
		first := harness.next(t)
		second := harness.next(t)
		responses := map[string]Response{first.RequestID: first, second.RequestID: second}
		assertOKType(t, responses[cancelID], cancelID, "cancel_accepted")
		assertFailureCode(t, responses[primaryID], primaryID, "operation_cancelled", "operation cancelled")
	}
	continued := request("sample_health", "request.repeat.health.continued", nil)
	if err := harness.send(continued); err != nil {
		t.Fatal(err)
	}
	assertOKType(t, harness.next(t), continued.RequestID, "health")
}

func TestEveryExitCancelsAndJoinsBeforeBackendClose(t *testing.T) {
	for name, terminate := range map[string]func(*controlHarness, context.CancelFunc){
		"EOF": func(harness *controlHarness, _ context.CancelFunc) {
			_ = harness.input.Close()
		},
		"parent cancellation": func(_ *controlHarness, cancel context.CancelFunc) {
			cancel()
		},
	} {
		t.Run(name, func(t *testing.T) {
			parent, cancelParent := context.WithCancel(context.Background())
			defer cancelParent()
			started := make(chan struct{})
			joined := make(chan struct{})
			closed := make(chan struct{})
			var closeBeforeJoin atomic.Bool
			backend := &controlBackend{}
			backend.connectFn = func(ctx context.Context, _ profile.Transport, _ profile.NormalizedEndpoint) error {
				close(started)
				<-ctx.Done()
				close(joined)
				return ctx.Err()
			}
			backend.closeFn = func() error {
				select {
				case <-joined:
				default:
					closeBeforeJoin.Store(true)
				}
				close(closed)
				return nil
			}
			harness := setupPreparedHarnessContext(t, parent, backend)
			if err := harness.send(request("connect_transport", "request.lifecycle.connect", json.RawMessage(`{"transport":"quic"}`))); err != nil {
				t.Fatal(err)
			}
			<-started
			terminate(harness, cancelParent)
			err := harness.wait(time.Second)
			if name == "EOF" && err != nil {
				t.Fatalf("EOF cleanup failed: %v", err)
			}
			if name == "parent cancellation" && !errors.Is(err, context.Canceled) {
				t.Fatalf("parent cancellation returned %v", err)
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("backend close did not run")
			}
			if closeBeforeJoin.Load() {
				t.Fatal("backend closed before active operation joined")
			}
		})
	}
}

func TestContextCancellationInterruptsAndJoinsOwnedReader(t *testing.T) {
	input := newBlockingReadCloser()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ServeWithBackendContext(ctx, bufio.NewReaderSize(input, maxRequestSize), input, io.Discard, &controlBackend{})
	}()
	select {
	case <-input.entered:
	case <-time.After(time.Second):
		t.Fatal("IPC reader did not enter the blocking read")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrReaderJoinTimeout) {
			t.Fatalf("reader cancellation did not join cleanly: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("owned reader was not interrupted and joined")
	}
	select {
	case <-input.closed:
	default:
		t.Fatal("Serve returned without closing the owned reader")
	}
}

func TestWriterFailureStillCancelsJoinsAndCloses(t *testing.T) {
	started := make(chan struct{})
	joined := make(chan struct{})
	var closeBeforeJoin atomic.Bool
	backend := &controlBackend{}
	backend.connectFn = func(ctx context.Context, _ profile.Transport, _ profile.NormalizedEndpoint) error {
		close(started)
		<-ctx.Done()
		close(joined)
		return ctx.Err()
	}
	backend.closeFn = func() error {
		select {
		case <-joined:
		default:
			closeBeforeJoin.Store(true)
		}
		return nil
	}
	harness := setupPreparedHarness(t, backend)
	primary := request("connect_transport", "request.writer.connect", json.RawMessage(`{"transport":"quic"}`))
	if err := harness.send(primary); err != nil {
		t.Fatal(err)
	}
	<-started
	harness.responses.fail.Store(true)
	if err := harness.send(request("cancel", "cancel.writer.connect", json.RawMessage(`{"target_request_id":"request.writer.connect"}`))); err != nil {
		t.Fatal(err)
	}
	if err := harness.wait(time.Second); err == nil || !strings.Contains(err.Error(), "write IPC response") {
		t.Fatalf("expected writer failure, got %v", err)
	}
	if closeBeforeJoin.Load() || backend.closeCalls.Load() != 1 {
		t.Fatalf("writer failure cleanup order was unsafe: before=%v closes=%d", closeBeforeJoin.Load(), backend.closeCalls.Load())
	}
}

func TestBackendIgnoringCancellationHitsBoundedJoinAndThenCloses(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	backend := &controlBackend{}
	backend.connectFn = func(context.Context, profile.Transport, profile.NormalizedEndpoint) error {
		close(started)
		<-release
		return nil
	}
	backend.closeFn = func() error {
		releaseOnce.Do(func() { close(release) })
		return nil
	}
	harness := setupPreparedHarness(t, backend)
	if err := harness.send(request("connect_transport", "request.ignore.cancel", json.RawMessage(`{"transport":"quic"}`))); err != nil {
		t.Fatal(err)
	}
	<-started
	startedAt := time.Now()
	if err := harness.input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := harness.wait(3 * time.Second); !errors.Is(err, ErrOperationJoinTimeout) {
		t.Fatalf("expected bounded join timeout, got %v", err)
	}
	elapsed := time.Since(startedAt)
	if elapsed < lifecycleJoinTimeout-150*time.Millisecond || elapsed > lifecycleJoinTimeout+750*time.Millisecond {
		t.Fatalf("operation join timeout escaped bound: %v", elapsed)
	}
	if backend.closeCalls.Load() != 1 {
		t.Fatalf("backend was not closed after join timeout: %d", backend.closeCalls.Load())
	}
}

func TestBackendCloseTimeoutIsBounded(t *testing.T) {
	release := make(chan struct{})
	backend := &controlBackend{closeFn: func() error {
		<-release
		return nil
	}}
	harness := startControlHarness(t, context.Background(), backend)
	startedAt := time.Now()
	if err := harness.input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := harness.wait(3 * time.Second); !errors.Is(err, ErrBackendCloseTimeout) {
		close(release)
		t.Fatalf("expected bounded close timeout, got %v", err)
	}
	elapsed := time.Since(startedAt)
	close(release)
	if elapsed < lifecycleJoinTimeout-150*time.Millisecond || elapsed > lifecycleJoinTimeout+750*time.Millisecond {
		t.Fatalf("backend close timeout escaped bound: %v", elapsed)
	}
}
