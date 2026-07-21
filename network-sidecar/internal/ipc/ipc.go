// Package ipc implements the versioned Rust/Go sidecar wire contract.
package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

const (
	ProtocolVersion = 1
	maxRequestSize  = 64 * 1_024
)

var ErrInvalidRequest = errors.New("invalid IPC request")

type Request struct {
	ProtocolVersion uint8   `json:"protocol_version"`
	RequestID       string  `json:"request_id"`
	Payload         Payload `json:"payload"`
}

type Payload struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

type Response struct {
	ProtocolVersion uint8                  `json:"protocol_version"`
	RequestID       string                 `json:"request_id"`
	Result          map[string]interface{} `json:"result"`
}

type Status struct {
	State           string  `json:"state"`
	ActiveProfileID *string `json:"active_profile_id"`
	ActiveTransport *string `json:"active_transport"`
	LastError       *string `json:"last_error"`
}

type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func Serve(reader *bufio.Reader, writer io.Writer) error {
	return ServeWithBackend(reader, writer, contractBackend{})
}

func ServeWithBackend(reader *bufio.Reader, writer io.Writer, backend Backend) error {
	encoder := json.NewEncoder(writer)
	current := newSessionWithBackend(backend)
	defer func() { _ = backend.Close() }()
	for {
		request, err := decodeRequest(reader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		response, stop := current.handle(request)
		if err := encoder.Encode(response); err != nil {
			return fmt.Errorf("write IPC response: %w", err)
		}
		if stop {
			return nil
		}
	}
}

func decodeRequest(reader *bufio.Reader) (Request, error) {
	message, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(message) > maxRequestSize {
		clear(message)
		return Request{}, ErrInvalidRequest
	}
	if errors.Is(err, io.EOF) && len(message) == 0 {
		return Request{}, io.EOF
	}
	if err != nil && !errors.Is(err, io.EOF) {
		clear(message)
		return Request{}, ErrInvalidRequest
	}
	message = bytes.TrimSuffix(message, []byte{'\n'})
	decoder := json.NewDecoder(bytes.NewReader(message))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		clear(message)
		return Request{}, ErrInvalidRequest
	}
	clear(message)
	if request.ProtocolVersion != ProtocolVersion || !validID(request.RequestID) || request.Payload.Type == "" {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

func handle(request Request) (Response, bool) {
	return newSession().handle(request)
}

func (current *session) handle(request Request) (Response, bool) {
	response := Response{ProtocolVersion: ProtocolVersion, RequestID: request.RequestID}
	switch request.Payload.Type {
	case "get_status":
		if !emptyData(request.Payload.Data) {
			return invalidData(response)
		}
		response.Result = success(map[string]interface{}{"type": "status", "data": current.status()})
		return response, false
	case "disconnect":
		if !emptyData(request.Payload.Data) {
			return invalidData(response)
		}
		if current.activeTransport != "" {
			if err := current.backend.Disconnect(context.Background()); err != nil {
				return current.backendFailure(response)
			}
		}
		if current.tunnelPrepared {
			if err := current.backend.Stop(context.Background()); err != nil {
				return current.backendFailure(response)
			}
		}
		if err := current.backend.Close(); err != nil {
			return current.backendFailure(response)
		}
		current.activeTransport = ""
		current.tunnelPrepared = false
		current.profile = nil
		current.lastError = nil
		response.Result = success(map[string]interface{}{"type": "acknowledged"})
		return response, true
	case "connect_transport":
		var data struct {
			Transport string `json:"transport"`
		}
		if !decodeData(request.Payload.Data, &data) || (data.Transport != "quic" && data.Transport != "wss" && data.Transport != "tcp") {
			return invalidData(response)
		}
		transport := profile.Transport(data.Transport)
		if current.profile == nil || !current.tunnelPrepared || current.activeTransport != "" || !current.profile.HasTransport(transport) {
			return invalidState(response)
		}
		endpoint, err := current.profile.Endpoint(transport)
		if err != nil {
			return invalidData(response)
		}
		if err := current.backend.Connect(context.Background(), transport, endpoint); err != nil {
			return current.backendFailure(response)
		}
		current.activeTransport = transport
		current.lastError = nil
		response.Result = success(map[string]interface{}{"type": "status", "data": current.status()})
		return response, false
	case "cancel":
		var data struct {
			OperationID string `json:"operation_id"`
		}
		if !decodeData(request.Payload.Data, &data) || !validID(data.OperationID) {
			return invalidData(response)
		}
		if err := current.backend.Cancel(data.OperationID); err != nil {
			return current.backendFailure(response)
		}
		response.Result = success(map[string]interface{}{"type": "acknowledged"})
		return response, false
	case "apply_profile":
		decoded, ok := decodeProfile(request.Payload.Data)
		if !ok {
			return invalidData(response)
		}
		if current.tunnelPrepared || current.activeTransport != "" {
			return invalidState(response)
		}
		current.profile = decoded
		current.lastError = nil
		response.Result = success(map[string]interface{}{"type": "acknowledged"})
		return response, false
	case "prepare_tunnel":
		if !emptyData(request.Payload.Data) {
			return invalidData(response)
		}
		if current.profile == nil || current.tunnelPrepared {
			return invalidState(response)
		}
		if err := current.backend.Prepare(context.Background(), current.profile); err != nil {
			return current.backendFailure(response)
		}
		current.tunnelPrepared = true
		current.lastError = nil
		response.Result = success(map[string]interface{}{"type": "status", "data": current.status()})
		return response, false
	case "disconnect_transport":
		if !emptyData(request.Payload.Data) {
			return invalidData(response)
		}
		if current.activeTransport == "" {
			return invalidState(response)
		}
		if err := current.backend.Disconnect(context.Background()); err != nil {
			return current.backendFailure(response)
		}
		current.activeTransport = ""
		current.lastError = nil
		response.Result = success(map[string]interface{}{"type": "status", "data": current.status()})
		return response, false
	case "stop_tunnel":
		if !emptyData(request.Payload.Data) {
			return invalidData(response)
		}
		if !current.tunnelPrepared || current.activeTransport != "" {
			return invalidState(response)
		}
		if err := current.backend.Stop(context.Background()); err != nil {
			return current.backendFailure(response)
		}
		current.tunnelPrepared = false
		current.lastError = nil
		response.Result = success(map[string]interface{}{"type": "status", "data": current.status()})
		return response, false
	case "sample_health":
		if !emptyData(request.Payload.Data) {
			return invalidData(response)
		}
		if current.activeTransport == "" {
			return invalidState(response)
		}
		health, err := current.backend.Health(context.Background())
		if err != nil || !health.valid() {
			return current.backendFailure(response)
		}
		response.Result = success(map[string]interface{}{"type": "health", "data": health})
		return response, false
	case "connect":
		if !emptyData(request.Payload.Data) {
			return invalidData(response)
		}
		response.Result = failure("sidecar_unavailable", "real networking remains disabled", true)
		return response, false
	default:
		response.Result = failure("invalid_configuration", "unknown request type", false)
		return response, false
	}
}

func emptyData(data json.RawMessage) bool {
	return len(data) == 0 || string(data) == "null"
}

func decodeData(data json.RawMessage, target interface{}) bool {
	if emptyData(data) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && decoder.Decode(&struct{}{}) == io.EOF
}

func invalidData(response Response) (Response, bool) {
	response.Result = failure("invalid_configuration", "invalid request payload", false)
	return response, false
}

func invalidState(response Response) (Response, bool) {
	response.Result = failure("invalid_state_transition", "invalid sidecar state transition", false)
	return response, false
}

func success(payload interface{}) map[string]interface{} {
	return map[string]interface{}{"Ok": payload}
}

func failure(code, message string, retryable bool) map[string]interface{} {
	return map[string]interface{}{"Err": Error{Code: code, Message: message, Retryable: retryable}}
}

func validID(value string) bool {
	if len(value) < 8 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character > unicode.MaxASCII || !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}
