package ipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

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

func TestDisabledNetworkingRequestsReturnStructuredErrors(t *testing.T) {
	requests := []Request{
		{ProtocolVersion: 1, RequestID: "request.test", Payload: Payload{Type: "apply_profile", Data: json.RawMessage(`{}`)}},
		{ProtocolVersion: 1, RequestID: "request.test", Payload: Payload{Type: "connect"}},
		{ProtocolVersion: 1, RequestID: "request.test", Payload: Payload{Type: "prepare_tunnel"}},
		{ProtocolVersion: 1, RequestID: "request.test", Payload: Payload{Type: "stop_tunnel"}},
		{ProtocolVersion: 1, RequestID: "request.test", Payload: Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"quic"}`)}},
		{ProtocolVersion: 1, RequestID: "request.test", Payload: Payload{Type: "disconnect_transport"}},
		{ProtocolVersion: 1, RequestID: "request.test", Payload: Payload{Type: "sample_health"}},
		{ProtocolVersion: 1, RequestID: "request.test", Payload: Payload{Type: "cancel", Data: json.RawMessage(`{"operation_id":"operation.test"}`)}},
	}
	for _, request := range requests {
		response, stop := handle(request)
		if stop {
			t.Fatal("disabled request stopped sidecar")
		}
		failure := response.Result["Err"].(Error)
		if failure.Code != "sidecar_unavailable" || !failure.Retryable {
			t.Fatalf("unexpected failure: %#v", failure)
		}
	}
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
