package vmexternalpeerlab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	SupervisorProtocolVersion = 1
	maximumSupervisorFrame    = 4096
)

type SupervisorOperation string

const (
	PrepareFixture SupervisorOperation = "prepare_fixture"
	BindTunnel     SupervisorOperation = "bind_tunnel"
	ApplyRoute     SupervisorOperation = "apply_route"
	VerifyRuntime  SupervisorOperation = "verify_runtime"
	DeleteRoute    SupervisorOperation = "delete_route"
	ReleaseRuntime SupervisorOperation = "release_runtime"
)

type SupervisorRequest struct {
	ProtocolVersion uint8               `json:"protocol_version"`
	Sequence        uint32              `json:"sequence"`
	Operation       SupervisorOperation `json:"operation"`
	InstanceID      string              `json:"instance_id,omitempty"`
	OperationID     string              `json:"operation_id,omitempty"`
	TunnelInterface string              `json:"tunnel_interface,omitempty"`
}

type SupervisorResponse struct {
	ProtocolVersion uint8  `json:"protocol_version"`
	Sequence        uint32 `json:"sequence"`
	OK              bool   `json:"ok"`
	Code            string `json:"code"`
}

func validToken(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validUTUN(value string) bool {
	if !strings.HasPrefix(value, "utun") || len(value) < 5 || len(value) > 12 || value == MihomoInterface {
		return false
	}
	for _, character := range value[4:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func (request SupervisorRequest) Validate() error {
	if request.ProtocolVersion != SupervisorProtocolVersion || request.Sequence == 0 {
		return errors.New("invalid supervisor protocol identity")
	}
	switch request.Operation {
	case PrepareFixture, ApplyRoute, VerifyRuntime, DeleteRoute, ReleaseRuntime:
		if request.InstanceID != "" || request.OperationID != "" || request.TunnelInterface != "" {
			return errors.New("supervisor operation contains unexpected authority")
		}
	case BindTunnel:
		if !validToken(request.InstanceID) || !validToken(request.OperationID) || !validUTUN(request.TunnelInterface) {
			return errors.New("invalid tunnel ownership facts")
		}
	default:
		return errors.New("unknown supervisor operation")
	}
	return nil
}

func (response SupervisorResponse) Validate(expectedSequence uint32) error {
	if response.ProtocolVersion != SupervisorProtocolVersion || response.Sequence != expectedSequence || response.Code == "" || len(response.Code) > 64 {
		return errors.New("invalid supervisor response")
	}
	if response.OK && response.Code != "ok" {
		return errors.New("successful supervisor response has a failure code")
	}
	if !response.OK && response.Code == "ok" {
		return errors.New("failed supervisor response has a success code")
	}
	if !validToken(response.Code) {
		return errors.New("invalid supervisor response code")
	}
	return nil
}

func decodeStrict[T any](reader io.Reader, value *T) error {
	limited := io.LimitReader(reader, maximumSupervisorFrame+1)
	bytesValue, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(bytesValue) == 0 || len(bytesValue) > maximumSupervisorFrame {
		return errors.New("invalid supervisor frame size")
	}
	decoder := json.NewDecoder(bytes.NewReader(bytesValue))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode supervisor frame: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("supervisor frame contains trailing data")
	}
	return nil
}

func DecodeSupervisorRequest(reader io.Reader) (SupervisorRequest, error) {
	var request SupervisorRequest
	if err := decodeStrict(reader, &request); err != nil {
		return SupervisorRequest{}, err
	}
	if err := request.Validate(); err != nil {
		return SupervisorRequest{}, err
	}
	return request, nil
}

func DecodeSupervisorResponse(reader io.Reader, expectedSequence uint32) (SupervisorResponse, error) {
	var response SupervisorResponse
	if err := decodeStrict(reader, &response); err != nil {
		return SupervisorResponse{}, err
	}
	if err := response.Validate(expectedSequence); err != nil {
		return SupervisorResponse{}, err
	}
	return response, nil
}

func EncodeSupervisorRequest(writer io.Writer, request SupervisorRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	return json.NewEncoder(writer).Encode(request)
}

func EncodeSupervisorResponse(writer io.Writer, response SupervisorResponse, expectedSequence uint32) error {
	if err := response.Validate(expectedSequence); err != nil {
		return err
	}
	return json.NewEncoder(writer).Encode(response)
}

func readSupervisorLine(reader *bufio.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("missing supervisor protocol reader")
	}
	frame, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(frame) > maximumSupervisorFrame {
		return nil, errors.New("supervisor frame is too large")
	}
	if errors.Is(err, io.EOF) && len(frame) == 0 {
		return nil, io.EOF
	}
	if err != nil || len(frame) < 2 {
		return nil, errors.New("truncated supervisor frame")
	}
	return frame, nil
}

// SupervisorRequestHandler is the root-owned, closed operation surface used
// by the client harness. The request has already passed strict schema and
// authority validation before HandleSupervisorRequest is called.
type SupervisorRequestHandler interface {
	HandleSupervisorRequest(context.Context, SupervisorRequest) error
}

// ServeSupervisorControl serves a single inherited full-duplex controller
// connection. There is no filesystem listener and therefore no independent
// process can discover or connect to this protocol surface.
func ServeSupervisorControl(ctx context.Context, connection net.Conn, handler SupervisorRequestHandler) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if connection == nil || handler == nil {
		return errors.New("missing supervisor control authority")
	}
	defer connection.Close()
	stopCancellation := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancellation()
	reader := bufio.NewReaderSize(connection, maximumSupervisorFrame+1)
	var previous uint32
	for {
		if deadline, ok := ctx.Deadline(); ok {
			_ = connection.SetReadDeadline(deadline)
		}
		frame, err := readSupervisorLine(reader)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		request, err := DecodeSupervisorRequest(bytes.NewReader(frame))
		if err != nil || request.Sequence != previous+1 {
			return errors.New("invalid supervisor request sequence")
		}
		previous = request.Sequence
		handleErr := handler.HandleSupervisorRequest(ctx, request)
		response := SupervisorResponse{
			ProtocolVersion: SupervisorProtocolVersion,
			Sequence:        request.Sequence,
			OK:              handleErr == nil,
			Code:            supervisorErrorCode(handleErr),
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = connection.SetWriteDeadline(deadline)
		}
		if err := EncodeSupervisorResponse(connection, response, request.Sequence); err != nil {
			return err
		}
		if handleErr != nil {
			return handleErr
		}
	}
}

func supervisorErrorCode(err error) string {
	if err == nil {
		return "ok"
	}
	return "operation_failed"
}

// ProtocolSupervisorClient implements the harness-side SupervisorClient over
// the one inherited connection. It exposes only the six typed operations;
// paths, routes, endpoints, commands, and process identifiers cannot cross
// this boundary.
type ProtocolSupervisorClient struct {
	mu         sync.Mutex
	connection net.Conn
	reader     *bufio.Reader
	sequence   uint32
}

func NewProtocolSupervisorClient(connection net.Conn) (*ProtocolSupervisorClient, error) {
	if connection == nil {
		return nil, errors.New("missing supervisor connection")
	}
	return &ProtocolSupervisorClient{
		connection: connection,
		reader:     bufio.NewReaderSize(connection, maximumSupervisorFrame+1),
	}, nil
}

func (client *ProtocolSupervisorClient) request(ctx context.Context, operation SupervisorOperation, instanceID, operationID, tunnelInterface string) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.connection == nil || client.reader == nil || client.sequence == ^uint32(0) {
		return errors.New("supervisor connection is unavailable")
	}
	sequence := client.sequence + 1
	request := SupervisorRequest{
		ProtocolVersion: SupervisorProtocolVersion,
		Sequence:        sequence,
		Operation:       operation,
		InstanceID:      instanceID,
		OperationID:     operationID,
		TunnelInterface: tunnelInterface,
	}
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := time.Now().Add(5 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := client.connection.SetDeadline(deadline); err != nil {
		return err
	}
	defer client.connection.SetDeadline(time.Time{}) //nolint:errcheck -- best-effort deadline reset on an owned pipe
	if err := EncodeSupervisorRequest(client.connection, request); err != nil {
		return err
	}
	frame, err := readSupervisorLine(client.reader)
	if err != nil {
		return err
	}
	response, err := DecodeSupervisorResponse(bytes.NewReader(frame), sequence)
	if err != nil {
		return err
	}
	client.sequence = sequence
	if !response.OK {
		return errors.New("supervisor operation refused")
	}
	return nil
}

func (client *ProtocolSupervisorClient) PrepareFixture(ctx context.Context) error {
	return client.request(ctx, PrepareFixture, "", "", "")
}

func (client *ProtocolSupervisorClient) BindTunnel(ctx context.Context, instanceID, operationID, tunnelInterface string) error {
	return client.request(ctx, BindTunnel, instanceID, operationID, tunnelInterface)
}

func (client *ProtocolSupervisorClient) ApplyRoute(ctx context.Context) error {
	return client.request(ctx, ApplyRoute, "", "", "")
}

func (client *ProtocolSupervisorClient) VerifyRuntime(ctx context.Context) error {
	return client.request(ctx, VerifyRuntime, "", "", "")
}

func (client *ProtocolSupervisorClient) DeleteRoute(ctx context.Context) error {
	return client.request(ctx, DeleteRoute, "", "", "")
}

func (client *ProtocolSupervisorClient) ReleaseRuntime(ctx context.Context) error {
	return client.request(ctx, ReleaseRuntime, "", "", "")
}

func (client *ProtocolSupervisorClient) Close() error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.connection == nil {
		return nil
	}
	err := client.connection.Close()
	client.connection = nil
	client.reader = nil
	return err
}

var _ SupervisorClient = (*ProtocolSupervisorClient)(nil)
