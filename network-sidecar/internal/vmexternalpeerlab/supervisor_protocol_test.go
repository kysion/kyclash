package vmexternalpeerlab

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

type recordingSupervisorHandler struct {
	requests []SupervisorRequest
	err      error
}

func (handler *recordingSupervisorHandler) HandleSupervisorRequest(_ context.Context, request SupervisorRequest) error {
	handler.requests = append(handler.requests, request)
	return handler.err
}

func TestSupervisorRequestRoundTrip(t *testing.T) {
	request := SupervisorRequest{
		ProtocolVersion: SupervisorProtocolVersion,
		Sequence:        7,
		Operation:       BindTunnel,
		InstanceID:      "instance-1",
		OperationID:     "operation-1",
		TunnelInterface: "utun7",
	}
	var encoded bytes.Buffer
	if err := EncodeSupervisorRequest(&encoded, request); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSupervisorRequest(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != request {
		t.Fatalf("decoded request differs: %#v", decoded)
	}
}

func TestSupervisorRequestRejectsAuthorityAndUnknownFields(t *testing.T) {
	for _, raw := range []string{
		`{"protocol_version":1,"sequence":1,"operation":"prepare_fixture","instance_id":"caller"}`,
		`{"protocol_version":1,"sequence":1,"operation":"bind_tunnel","instance_id":"i","operation_id":"o","tunnel_interface":"utun4094"}`,
		`{"protocol_version":1,"sequence":1,"operation":"shell"}`,
		`{"protocol_version":1,"sequence":1,"operation":"delete_route","path":"/tmp/x"}`,
	} {
		if _, err := DecodeSupervisorRequest(strings.NewReader(raw)); err == nil {
			t.Fatalf("accepted invalid request: %s", raw)
		}
	}
}

func TestSupervisorResponseRequiresExactSequence(t *testing.T) {
	response := SupervisorResponse{ProtocolVersion: SupervisorProtocolVersion, Sequence: 9, OK: true, Code: "ok"}
	var encoded bytes.Buffer
	if err := EncodeSupervisorResponse(&encoded, response, 9); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSupervisorResponse(bytes.NewReader(encoded.Bytes()), 8); err == nil {
		t.Fatal("accepted a response for another request")
	}
}

func TestSupervisorFrameIsBounded(t *testing.T) {
	raw := strings.Repeat("x", maximumSupervisorFrame+1)
	if _, err := DecodeSupervisorRequest(strings.NewReader(raw)); err == nil {
		t.Fatal("accepted an oversized frame")
	}
}

func TestProtocolSupervisorClientServesClosedTypedSequence(t *testing.T) {
	server, clientConnection := net.Pipe()
	handler := &recordingSupervisorHandler{}
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- ServeSupervisorControl(context.Background(), server, handler)
	}()
	client, err := NewProtocolSupervisorClient(clientConnection)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, operation := range []func(context.Context) error{
		client.PrepareFixture,
		func(ctx context.Context) error { return client.BindTunnel(ctx, "instance-1", "operation-1", "utun7") },
		client.ApplyRoute,
		client.VerifyRuntime,
		client.DeleteRoute,
		client.ReleaseRuntime,
	} {
		if err := operation(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	if len(handler.requests) != 6 {
		t.Fatalf("got %d requests", len(handler.requests))
	}
	for index, request := range handler.requests {
		if request.Sequence != uint32(index+1) {
			t.Fatalf("request %d has sequence %d", index, request.Sequence)
		}
	}
}

func TestSupervisorControlFailsClosedOnSkippedSequence(t *testing.T) {
	server, client := net.Pipe()
	handler := &recordingSupervisorHandler{}
	result := make(chan error, 1)
	go func() { result <- ServeSupervisorControl(context.Background(), server, handler) }()
	_, err := client.Write([]byte(`{"protocol_version":1,"sequence":2,"operation":"prepare_fixture"}` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("skipped sequence was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("server did not reject skipped sequence")
	}
	_ = client.Close()
}
