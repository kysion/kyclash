package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

type faultBackend struct {
	fail       string
	closeCalls int
}

func (backend *faultBackend) Prepare(context.Context, *profile.Profile) error {
	if backend.fail == "prepare" {
		return ErrBackendUnavailable
	}
	return nil
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

func (backend *faultBackend) Cancel(string) error { return nil }
func (backend *faultBackend) Close() error {
	backend.closeCalls++
	return nil
}

func TestServeMatchesRustStatusAndDisconnectWireFormat(t *testing.T) {
	input := strings.Join([]string{
		`{"protocol_version":1,"request_id":"request.status","payload":{"type":"get_status"}}`,
		`{"protocol_version":1,"request_id":"request.stop","payload":{"type":"disconnect"}}`,
		"",
	}, "\n")
	var output bytes.Buffer
	if err := Serve(bufio.NewReader(strings.NewReader(input)), &output); err != nil {
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
	fixture, err := os.ReadFile("../../../schemas/fixtures/network-ipc-v1.status.json")
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
		{ProtocolVersion: 1, RequestID: "request.profile", Payload: Payload{Type: "apply_profile", Data: profileData}},
		{ProtocolVersion: 1, RequestID: "request.prepare", Payload: Payload{Type: "prepare_tunnel"}},
		{ProtocolVersion: 1, RequestID: "request.quic", Payload: Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"quic"}`)}},
		{ProtocolVersion: 1, RequestID: "request.health", Payload: Payload{Type: "sample_health"}},
		{ProtocolVersion: 1, RequestID: "request.close_quic", Payload: Payload{Type: "disconnect_transport"}},
		{ProtocolVersion: 1, RequestID: "request.wss", Payload: Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"wss"}`)}},
		{ProtocolVersion: 1, RequestID: "request.close_wss", Payload: Payload{Type: "disconnect_transport"}},
		{ProtocolVersion: 1, RequestID: "request.stop", Payload: Payload{Type: "stop_tunnel"}},
	}
	for _, request := range requests {
		response, stop := current.handle(request)
		if stop || response.Result["Err"] != nil {
			t.Fatalf("request %s failed: %#v", request.Payload.Type, response)
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
	assertInvalidState(Request{ProtocolVersion: 1, RequestID: "request.early", Payload: Payload{Type: "prepare_tunnel"}})
	current.handle(Request{ProtocolVersion: 1, RequestID: "request.profile", Payload: Payload{Type: "apply_profile", Data: profileData}})
	current.handle(Request{ProtocolVersion: 1, RequestID: "request.prepare", Payload: Payload{Type: "prepare_tunnel"}})
	current.handle(Request{ProtocolVersion: 1, RequestID: "request.quic", Payload: Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"quic"}`)}})
	assertInvalidState(Request{ProtocolVersion: 1, RequestID: "request.wss", Payload: Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"wss"}`)}})
}

func TestRequestValidationFailsClosed(t *testing.T) {
	for _, input := range []string{
		`{}`,
		`{"protocol_version":2,"request_id":"request.test","payload":{"type":"get_status"}}`,
		`{"protocol_version":1,"request_id":"../bad","payload":{"type":"get_status"}}`,
		`{"protocol_version":1,"request_id":"request.test","payload":{"type":"get_status"},"unknown":true}`,
	} {
		if _, err := decodeRequest(bufio.NewReader(strings.NewReader(input + "\n"))); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("expected invalid request for %q, got %v", input, err)
		}
	}
}

func TestBackendFailureNeverAdvancesSessionState(t *testing.T) {
	profileData, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	backend := &faultBackend{fail: "prepare"}
	current := newSessionWithBackend(backend)
	current.handle(Request{ProtocolVersion: 1, RequestID: "request.profile", Payload: Payload{Type: "apply_profile", Data: profileData}})
	response, _ := current.handle(Request{ProtocolVersion: 1, RequestID: "request.prepare", Payload: Payload{Type: "prepare_tunnel"}})
	if current.tunnelPrepared || response.Result["Err"].(Error).Code != "sidecar_unavailable" {
		t.Fatalf("prepare failure advanced state: %#v", current.status())
	}

	backend.fail = ""
	current.handle(Request{ProtocolVersion: 1, RequestID: "request.prepare_ok", Payload: Payload{Type: "prepare_tunnel"}})
	backend.fail = "connect"
	response, _ = current.handle(Request{ProtocolVersion: 1, RequestID: "request.connect", Payload: Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"quic"}`)}})
	if current.activeTransport != "" || response.Result["Err"].(Error).Code != "sidecar_unavailable" {
		t.Fatalf("connect failure advanced state: %#v", current.status())
	}
}

func TestHealthMatchesSharedFixture(t *testing.T) {
	current := newSessionWithBackend(&faultBackend{})
	current.tunnelPrepared = true
	current.activeTransport = profile.QUIC
	response, stop := current.handle(Request{ProtocolVersion: 1, RequestID: "request.health", Payload: Payload{Type: "sample_health"}})
	if stop {
		t.Fatal("health stopped session")
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../../schemas/fixtures/network-ipc-v1.health.json")
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
	if err := ServeWithBackend(bufio.NewReader(strings.NewReader("")), &bytes.Buffer{}, backend); err != nil {
		t.Fatal(err)
	}
	if backend.closeCalls != 1 {
		t.Fatalf("expected one EOF cleanup, got %d", backend.closeCalls)
	}
}
