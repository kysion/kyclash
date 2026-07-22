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
	"sync/atomic"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/identifier"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

const (
	ProtocolVersion = 2
	maxRequestSize  = 64 * 1_024
)

var ErrInvalidRequest = errors.New("invalid IPC request")

var (
	ErrOperationJoinTimeout = errors.New("IPC operation join timeout")
	ErrBackendCloseTimeout  = errors.New("IPC backend close timeout")
	ErrReaderJoinTimeout    = errors.New("IPC reader join timeout")
)

const lifecycleJoinTimeout = 2 * time.Second

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

func Serve(reader *bufio.Reader, readerCloser io.Closer, writer io.Writer) error {
	return ServeWithBackend(reader, readerCloser, writer, contractBackend{})
}

func ServeWithBackend(reader *bufio.Reader, readerCloser io.Closer, writer io.Writer, backend Backend) error {
	return ServeWithBackendContext(context.Background(), reader, readerCloser, writer, backend)
}

// ServeWithBackendContext is the cancellable process boundary used by the
// real sidecar. Cancellation is deliberately handled at the IPC owner rather
// than through a second backend cancellation channel: it cancels the exact
// context of an in-flight connect or health operation, waits for that operation
// to join, and only then runs disconnect or close. This ordering prevents
// cleanup from racing userspace WireGuard work and leaving an owned device
// behind. readerCloser must own and interrupt reader's underlying input.
func ServeWithBackendContext(ctx context.Context, reader *bufio.Reader, readerCloser io.Closer, writer io.Writer, backend Backend) (serveErr error) {
	if reader == nil || readerCloser == nil || backend == nil {
		return ErrInvalidRequest
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ownerContext, cancelOwner := context.WithCancel(context.Background())
	encoder := json.NewEncoder(writer)
	current := newSessionWithBackend(backend)
	type decodedRequest struct {
		request Request
		err     error
	}
	type activePrimary struct {
		operation   *cancellableOperation
		cancel      context.CancelFunc
		winner      atomic.Uint32
		controlSeen bool
		lateCancel  *Request
	}
	type operationResult struct {
		active        *activePrimary
		backendResult backendOperationResult
		response      Response
		cancelled     bool
		err           error
	}
	requests := make(chan decodedRequest)
	operations := make(chan operationResult, 1)
	readerDone := make(chan struct{})
	var active *activePrimary

	joinActive := func() bool {
		if active == nil {
			return true
		}
		value := active
		value.winner.CompareAndSwap(operationRaceRunning, operationRaceCancelWon)
		value.cancel()
		timer := time.NewTimer(lifecycleJoinTimeout)
		defer timer.Stop()
		select {
		case result := <-operations:
			active = nil
			return result.active == value
		case <-timer.C:
			active = nil
			return false
		}
	}
	defer func() {
		// Closing the owned input first interrupts a reader blocked in ReadSlice.
		// The owner context remains live until active backend work has joined so
		// its result cannot be dropped instead of reaching the join channel.
		_ = readerCloser.Close()
		if !joinActive() {
			serveErr = errors.Join(serveErr, ErrOperationJoinTimeout)
		}
		cancelOwner()
		readerTimer := time.NewTimer(lifecycleJoinTimeout)
		select {
		case <-readerDone:
		case <-readerTimer.C:
			serveErr = errors.Join(serveErr, ErrReaderJoinTimeout)
		}
		readerTimer.Stop()
		closed := make(chan error, 1)
		go func() { closed <- backend.Close() }()
		timer := time.NewTimer(lifecycleJoinTimeout)
		defer timer.Stop()
		select {
		case err := <-closed:
			if err != nil {
				serveErr = errors.Join(serveErr, err)
			}
		case <-timer.C:
			serveErr = errors.Join(serveErr, ErrBackendCloseTimeout)
		}
	}()

	go func() {
		defer close(readerDone)
		defer close(requests)
		for {
			request, err := decodeRequest(reader)
			select {
			case requests <- decodedRequest{request: request, err: err}:
			case <-ownerContext.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	startOperation := func(operation *cancellableOperation) {
		operationContext, cancel := context.WithCancel(ownerContext)
		value := &activePrimary{operation: operation, cancel: cancel}
		active = value
		go func() {
			backendResult := operation.run(operationContext, backend)
			completionWon := value.winner.CompareAndSwap(operationRaceRunning, operationRaceCompletionWon)
			result := operationResult{active: value, backendResult: backendResult, cancelled: !completionWon}
			// The owner applies all successful completion state changes after
			// receiving this result, so concurrent Cancel never races profile or
			// carrier facts in the session object.
			if !completionWon {
				result.response, result.err = current.cancelCancellable(operation, backendResult)
			}
			select {
			case operations <- result:
			case <-ownerContext.Done():
			}
		}()
	}
	writeResponse := func(response Response) error {
		if err := encoder.Encode(response); err != nil {
			return fmt.Errorf("write IPC response: %w", err)
		}
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case decoded, ok := <-requests:
			if !ok {
				return nil
			}
			if errors.Is(decoded.err, io.EOF) {
				return nil
			}
			if decoded.err != nil {
				return decoded.err
			}
			request := decoded.request
			if active != nil {
				if request.Payload.Type != "cancel" || active.controlSeen {
					return ErrInvalidRequest
				}
				targetRequestID, valid := decodeCancelTarget(request)
				if !valid || targetRequestID != active.operation.request.RequestID {
					return ErrInvalidRequest
				}
				active.controlSeen = true
				if active.winner.CompareAndSwap(operationRaceRunning, operationRaceCancelWon) {
					active.cancel()
					if err := writeResponse(cancelAccepted(request.RequestID, targetRequestID)); err != nil {
						return err
					}
				} else {
					late := request
					active.lateCancel = &late
				}
				continue
			}
			if request.Payload.Type == "cancel" {
				if _, valid := decodeCancelTarget(request); !valid {
					response := Response{ProtocolVersion: ProtocolVersion, RequestID: request.RequestID}
					response, _ = invalidData(response)
					if err := writeResponse(response); err != nil {
						return err
					}
				} else if err := writeResponse(cancelTooLate(request.RequestID)); err != nil {
					return err
				}
				continue
			}
			if request.Payload.Type == "connect_transport" || request.Payload.Type == "sample_health" {
				operation, response, valid := current.prepareCancellable(request)
				if !valid {
					if err := writeResponse(response); err != nil {
						return err
					}
					continue
				}
				startOperation(operation)
				continue
			}
			response, stop := current.handleWithContext(ctx, request)
			if err := writeResponse(response); err != nil {
				return err
			}
			if stop {
				return nil
			}
		case result := <-operations:
			if active == nil || result.active != active {
				return ErrInvalidRequest
			}
			completed := active
			completed.cancel()
			active = nil
			if result.err != nil {
				return result.err
			}
			if !result.cancelled {
				result.response = current.completeCancellable(completed.operation, result.backendResult)
			}
			if err := writeResponse(result.response); err != nil {
				return err
			}
			if !result.cancelled && completed.lateCancel != nil {
				if err := writeResponse(cancelTooLate(completed.lateCancel.RequestID)); err != nil {
					return err
				}
			}
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
	// IPC is LF-delimited.  EOF with a non-empty final fragment is truncated
	// input even when that fragment happens to be valid JSON.
	if err != nil {
		clear(message)
		return Request{}, ErrInvalidRequest
	}
	message = message[:len(message)-1]
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
	return current.handleWithContext(context.Background(), request)
}

func (current *session) handleWithContext(ctx context.Context, request Request) (Response, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
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
			if err := current.backend.Disconnect(ctx); err != nil {
				return current.backendFailure(response)
			}
		}
		if current.tunnelPrepared {
			if err := current.backend.Stop(ctx); err != nil {
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
		if err := current.backend.Connect(ctx, transport, endpoint); err != nil {
			return current.backendFailure(response)
		}
		current.activeTransport = transport
		current.lastError = nil
		response.Result = success(map[string]interface{}{"type": "status", "data": current.status()})
		return response, false
	case "cancel":
		if _, ok := decodeCancelTarget(request); !ok {
			return invalidData(response)
		}
		return cancelTooLate(request.RequestID), false
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
		facts, err := current.backend.Prepare(ctx, current.profile, request.RequestID)
		if err != nil {
			return current.backendFailure(response)
		}
		current.tunnelPrepared = true
		current.lastError = nil
		response.Result = success(map[string]interface{}{"type": "tunnel_prepared", "data": facts})
		return response, false
	case "disconnect_transport":
		if !emptyData(request.Payload.Data) {
			return invalidData(response)
		}
		if current.activeTransport == "" {
			return invalidState(response)
		}
		if err := current.backend.Disconnect(ctx); err != nil {
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
		if err := current.backend.Stop(ctx); err != nil {
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
		health, err := current.backend.Health(ctx)
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
	return identifier.Valid(value)
}
