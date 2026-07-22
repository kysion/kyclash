package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/ipc"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

const actualLabBlackholeChildEnvironment = "KYCLASH_ACTUAL_LAB_BLACKHOLE_CHILD"

func TestActualLabBlackholeChild(t *testing.T) {
	if os.Getenv(actualLabBlackholeChildEnvironment) != "1" {
		return
	}
	// The peer owns only the reviewed ProbeAddress. The adjacent peer port is
	// intentionally closed, so the userspace TCP health dial remains bounded
	// by the IPC operation context while the encrypted loopback carrier stays
	// connected.
	blackhole := netip.MustParseAddrPort("10.88.0.2:38081")
	if err := runWithProbeAddress(nil, os.Stdin, os.Stdout, blackhole); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

type actualLabChild struct {
	command   *exec.Cmd
	cancel    context.CancelFunc
	input     io.WriteCloser
	requests  *json.Encoder
	responses *json.Decoder
}

func startActualLabChild(t *testing.T) (*actualLabChild, labHandshake) {
	t.Helper()
	childContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	command := exec.CommandContext(childContext, os.Args[0], "-test.run=^TestActualLabBlackholeChild$")
	command.Env = append(os.Environ(), actualLabBlackholeChildEnvironment+"=1")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	child := &actualLabChild{command: command, cancel: cancel, input: input, requests: json.NewEncoder(input), responses: json.NewDecoder(output)}
	t.Cleanup(func() {
		child.cancel()
		_ = child.input.Close()
		if child.command.ProcessState == nil {
			_ = child.command.Process.Kill()
			_ = child.command.Wait()
		}
	})
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))
	bootstrap := map[string]interface{}{
		"protocol_version": ipc.ProtocolVersion,
		"instance_id":      "actual_health_child",
		"auth_token":       secret,
		"private_key":      secret,
	}
	if err := child.requests.Encode(bootstrap); err != nil {
		t.Fatal(err)
	}
	var handshake labHandshake
	if err := child.responses.Decode(&handshake); err != nil {
		t.Fatal(err)
	}
	if handshake.ProtocolVersion != ipc.ProtocolVersion || handshake.InstanceID != "actual_health_child" {
		t.Fatalf("unexpected lab child handshake: %#v", handshake)
	}
	return child, handshake
}

func (child *actualLabChild) send(t *testing.T, request ipc.Request) {
	t.Helper()
	if err := child.requests.Encode(request); err != nil {
		t.Fatal(err)
	}
}

func (child *actualLabChild) read(t *testing.T, requestID string) ipc.Response {
	t.Helper()
	var response ipc.Response
	if err := child.responses.Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.ProtocolVersion != ipc.ProtocolVersion || response.RequestID != requestID {
		t.Fatalf("unexpected correlated response: %#v", response)
	}
	return response
}

func (child *actualLabChild) exchange(t *testing.T, request ipc.Request) ipc.Response {
	t.Helper()
	child.send(t, request)
	return child.read(t, request.RequestID)
}

func requireLabSuccess(t *testing.T, response ipc.Response) {
	t.Helper()
	if _, ok := response.Result["Ok"]; !ok {
		t.Fatalf("expected successful lab IPC response: %#v", response)
	}
}

func requireLabFailure(t *testing.T, response ipc.Response, requestID, code string) {
	t.Helper()
	if response.ProtocolVersion != ipc.ProtocolVersion || response.RequestID != requestID {
		t.Fatalf("unexpected correlated lab response: %#v", response)
	}
	encoded, err := json.Marshal(response.Result["Err"])
	if err != nil {
		t.Fatal(err)
	}
	var failure ipc.Error
	if json.Unmarshal(encoded, &failure) != nil || failure.Code != code || failure.Retryable {
		t.Fatalf("unexpected typed lab failure: %#v", response)
	}
}

func requireLabCancelAccepted(t *testing.T, response ipc.Response, requestID, targetRequestID string) {
	t.Helper()
	if response.ProtocolVersion != ipc.ProtocolVersion || response.RequestID != requestID {
		t.Fatalf("unexpected correlated lab response: %#v", response)
	}
	encoded, err := json.Marshal(response.Result["Ok"])
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Type string `json:"type"`
		Data struct {
			TargetRequestID string `json:"target_request_id"`
		} `json:"data"`
	}
	if json.Unmarshal(encoded, &payload) != nil || payload.Type != "cancel_accepted" || payload.Data.TargetRequestID != targetRequestID {
		t.Fatalf("unexpected typed cancel acceptance: %#v", response)
	}
}

func TestActualLabChildCancelUnblocksHealthAndContinuesIPC(t *testing.T) {
	child, handshake := startActualLabChild(t)
	profileData, err := json.Marshal(handshake.LabProfile)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []ipc.Request{
		{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.actual.profile", Payload: ipc.Payload{Type: "apply_profile", Data: profileData}},
		{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.actual.prepare", Payload: ipc.Payload{Type: "prepare_tunnel"}},
		{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.actual.connect", Payload: ipc.Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"quic"}`)}},
	} {
		requireLabSuccess(t, child.exchange(t, request))
	}

	healthRequest := ipc.Request{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.actual.health", Payload: ipc.Payload{Type: "sample_health"}}
	child.send(t, healthRequest)
	type responseResult struct {
		response ipc.Response
		err      error
	}
	firstResponse := make(chan responseResult, 1)
	go func() {
		var response ipc.Response
		err := child.responses.Decode(&response)
		firstResponse <- responseResult{response: response, err: err}
	}()
	select {
	case result := <-firstResponse:
		t.Fatalf("blackholed health returned before cancellation: response=%#v err=%v", result.response, result.err)
	case <-time.After(150 * time.Millisecond):
	}

	started := time.Now()
	cancelRequest := ipc.Request{
		ProtocolVersion: ipc.ProtocolVersion,
		RequestID:       "cancel.actual.health",
		Payload: ipc.Payload{
			Type: "cancel",
			Data: json.RawMessage(`{"target_request_id":"request.actual.health"}`),
		},
	}
	child.send(t, cancelRequest)
	select {
	case result := <-firstResponse:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.response.RequestID != cancelRequest.RequestID {
			t.Fatalf("cancel response lost correlation: %#v", result.response)
		}
		requireLabCancelAccepted(t, result.response, cancelRequest.RequestID, healthRequest.RequestID)
	case <-time.After(2 * time.Second):
		t.Fatal("actual lab child did not acknowledge health cancellation")
	}
	requireLabFailure(t, child.read(t, healthRequest.RequestID), healthRequest.RequestID, "operation_cancelled")
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("actual encrypted-loopback health cancellation exceeded bound: %v", elapsed)
	}

	requireLabSuccess(t, child.exchange(t, ipc.Request{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.actual.status", Payload: ipc.Payload{Type: "get_status"}}))
	requireLabSuccess(t, child.exchange(t, ipc.Request{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.actual.disconnect_transport", Payload: ipc.Payload{Type: "disconnect_transport"}}))
	requireLabSuccess(t, child.exchange(t, ipc.Request{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.actual.stop", Payload: ipc.Payload{Type: "stop_tunnel"}}))
	requireLabSuccess(t, child.exchange(t, ipc.Request{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.actual.disconnect", Payload: ipc.Payload{Type: "disconnect"}}))
	if err := child.input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.command.Wait(); err != nil {
		t.Fatal(err)
	}
	child.cancel()
}

func TestActualLabChildCancelUnblocksQUICBlackholeAndAllowsFallbacks(t *testing.T) {
	child, handshake := startActualLabChild(t)
	for index := range handshake.LabProfile.Transports.Endpoints {
		endpoint := &handshake.LabProfile.Transports.Endpoints[index]
		if endpoint.Transport == profile.QUIC {
			endpoint.URL = handshake.CancelEndpoint
		}
	}
	profileData, err := json.Marshal(handshake.LabProfile)
	if err != nil {
		t.Fatal(err)
	}
	for _, setup := range []ipc.Request{
		{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.actual.quic.profile", Payload: ipc.Payload{Type: "apply_profile", Data: profileData}},
		{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.actual.quic.prepare", Payload: ipc.Payload{Type: "prepare_tunnel"}},
	} {
		requireLabSuccess(t, child.exchange(t, setup))
	}

	primary := ipc.Request{
		ProtocolVersion: ipc.ProtocolVersion,
		RequestID:       "request.actual.quic.blackhole",
		Payload:         ipc.Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"quic"}`)},
	}
	child.send(t, primary)
	type responseResult struct {
		response ipc.Response
		err      error
	}
	firstResponse := make(chan responseResult, 1)
	go func() {
		var response ipc.Response
		err := child.responses.Decode(&response)
		firstResponse <- responseResult{response: response, err: err}
	}()
	select {
	case result := <-firstResponse:
		t.Fatalf("QUIC blackhole returned before cancellation: response=%#v err=%v", result.response, result.err)
	case <-time.After(150 * time.Millisecond):
	}

	started := time.Now()
	cancel := ipc.Request{
		ProtocolVersion: ipc.ProtocolVersion,
		RequestID:       "cancel.actual.quic.blackhole",
		Payload: ipc.Payload{
			Type: "cancel",
			Data: json.RawMessage(`{"target_request_id":"request.actual.quic.blackhole"}`),
		},
	}
	child.send(t, cancel)
	select {
	case result := <-firstResponse:
		if result.err != nil {
			t.Fatal(result.err)
		}
		requireLabCancelAccepted(t, result.response, cancel.RequestID, primary.RequestID)
	case <-time.After(2 * time.Second):
		t.Fatal("actual child did not acknowledge QUIC blackhole cancellation")
	}
	requireLabFailure(t, child.read(t, primary.RequestID), primary.RequestID, "operation_cancelled")
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("actual QUIC blackhole cancellation exceeded bound: %v", elapsed)
	}

	for index, transport := range []profile.Transport{profile.WSS, profile.TCP} {
		connect := ipc.Request{
			ProtocolVersion: ipc.ProtocolVersion,
			RequestID:       fmt.Sprintf("request.actual.fallback.%d", index),
			Payload:         ipc.Payload{Type: "connect_transport", Data: json.RawMessage(`{"transport":"` + string(transport) + `"}`)},
		}
		requireLabSuccess(t, child.exchange(t, connect))
		disconnect := ipc.Request{ProtocolVersion: ipc.ProtocolVersion, RequestID: fmt.Sprintf("request.actual.fallback.disconnect.%d", index), Payload: ipc.Payload{Type: "disconnect_transport"}}
		requireLabSuccess(t, child.exchange(t, disconnect))
	}
	requireLabSuccess(t, child.exchange(t, ipc.Request{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.actual.quic.stop", Payload: ipc.Payload{Type: "stop_tunnel"}}))
	requireLabSuccess(t, child.exchange(t, ipc.Request{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.actual.quic.disconnect", Payload: ipc.Payload{Type: "disconnect"}}))
	if err := child.input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.command.Wait(); err != nil {
		t.Fatal(err)
	}
	child.cancel()
}
