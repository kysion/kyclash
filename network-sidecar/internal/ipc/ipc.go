// Package ipc implements the versioned Rust/Go sidecar wire contract.
package ipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
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
	encoder := json.NewEncoder(writer)
	for {
		request, err := decodeRequest(reader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		response, stop := handle(request)
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
	response := Response{ProtocolVersion: ProtocolVersion, RequestID: request.RequestID}
	if len(request.Payload.Data) != 0 && string(request.Payload.Data) != "null" {
		response.Result = failure("invalid_configuration", "request payload data is not accepted", false)
		return response, false
	}
	switch request.Payload.Type {
	case "get_status":
		response.Result = success(map[string]interface{}{
			"type": "status",
			"data": Status{State: "disconnected"},
		})
		return response, false
	case "disconnect":
		response.Result = success(map[string]interface{}{"type": "acknowledged"})
		return response, true
	case "apply_profile", "connect", "cancel":
		response.Result = failure("sidecar_unavailable", "real networking remains disabled", true)
		return response, false
	default:
		response.Result = failure("invalid_configuration", "unknown request type", false)
		return response, false
	}
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
