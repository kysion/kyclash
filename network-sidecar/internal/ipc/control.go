package ipc

import (
	"context"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

const (
	operationRaceRunning uint32 = iota
	operationRaceCancelWon
	operationRaceCompletionWon
)

type cancellableOperation struct {
	request   Request
	transport profile.Transport
	endpoint  profile.NormalizedEndpoint
}

type backendOperationResult struct {
	health              Health
	privateReachability PrivateReachability
	err                 error
}

func (current *session) prepareCancellable(request Request) (*cancellableOperation, Response, bool) {
	response := Response{ProtocolVersion: ProtocolVersion, RequestID: request.RequestID}
	switch request.Payload.Type {
	case "connect_transport":
		var data struct {
			Transport string `json:"transport"`
		}
		if !decodeData(request.Payload.Data, &data) || (data.Transport != "quic" && data.Transport != "wss" && data.Transport != "tcp") {
			response, _ = invalidData(response)
			return nil, response, false
		}
		transport := profile.Transport(data.Transport)
		if current.profile == nil || !current.tunnelPrepared || current.activeTransport != "" || !current.profile.HasTransport(transport) {
			response, _ = invalidState(response)
			return nil, response, false
		}
		endpoint, err := current.profile.Endpoint(transport)
		if err != nil {
			response, _ = invalidData(response)
			return nil, response, false
		}
		return &cancellableOperation{request: request, transport: transport, endpoint: endpoint}, Response{}, true
	case "sample_health":
		if !emptyData(request.Payload.Data) {
			response, _ = invalidData(response)
			return nil, response, false
		}
		if current.activeTransport == "" {
			response, _ = invalidState(response)
			return nil, response, false
		}
		return &cancellableOperation{request: request}, Response{}, true
	case "sample_private_reachability":
		if !emptyData(request.Payload.Data) {
			response, _ = invalidData(response)
			return nil, response, false
		}
		if current.activeTransport == "" {
			response, _ = invalidState(response)
			return nil, response, false
		}
		if _, ok := current.backend.(PrivateReachabilityBackend); !ok {
			response, _ = invalidState(response)
			return nil, response, false
		}
		return &cancellableOperation{request: request}, Response{}, true
	default:
		response, _ = invalidState(response)
		return nil, response, false
	}
}

func (operation *cancellableOperation) run(ctx context.Context, backend Backend) backendOperationResult {
	switch operation.request.Payload.Type {
	case "connect_transport":
		return backendOperationResult{err: backend.Connect(ctx, operation.transport, operation.endpoint)}
	case "sample_health":
		health, err := backend.Health(ctx)
		return backendOperationResult{health: health, err: err}
	case "sample_private_reachability":
		probe, ok := backend.(PrivateReachabilityBackend)
		if !ok {
			return backendOperationResult{err: ErrBackendUnavailable}
		}
		reachability, err := probe.PrivateReachability(ctx)
		return backendOperationResult{privateReachability: reachability, err: err}
	default:
		return backendOperationResult{err: ErrBackendUnavailable}
	}
}

func (current *session) completeCancellable(operation *cancellableOperation, result backendOperationResult) Response {
	response := Response{ProtocolVersion: ProtocolVersion, RequestID: operation.request.RequestID}
	if result.err != nil {
		response, _ = current.backendFailure(response)
		return response
	}
	switch operation.request.Payload.Type {
	case "connect_transport":
		current.activeTransport = operation.transport
		current.lastError = nil
		response.Result = success(map[string]interface{}{"type": "status", "data": current.status()})
	case "sample_health":
		if !result.health.valid() {
			response, _ = current.backendFailure(response)
			return response
		}
		response.Result = success(map[string]interface{}{"type": "health", "data": result.health})
	case "sample_private_reachability":
		if !result.privateReachability.valid() {
			response, _ = current.backendFailure(response)
			return response
		}
		response.Result = success(map[string]interface{}{
			"type": "private_reachability",
			"data": result.privateReachability,
		})
	default:
		response, _ = current.backendFailure(response)
	}
	return response
}

func (current *session) cancelCancellable(operation *cancellableOperation, result backendOperationResult) (Response, error) {
	if operation.request.Payload.Type == "connect_transport" && result.err == nil {
		// Cancellation linearized before completion, but the backend completed
		// concurrently. Restore the prepared/no-carrier state before reporting a
		// clean cancellation.
		if err := current.backend.Disconnect(context.Background()); err != nil {
			return Response{}, err
		}
	}
	response := Response{ProtocolVersion: ProtocolVersion, RequestID: operation.request.RequestID}
	response.Result = failure("operation_cancelled", "operation cancelled", false)
	return response, nil
}

func decodeCancelTarget(request Request) (string, bool) {
	var decoded struct {
		TargetRequestID string `json:"target_request_id"`
	}
	if !decodeData(request.Payload.Data, &decoded) || !validID(decoded.TargetRequestID) || decoded.TargetRequestID == request.RequestID {
		return "", false
	}
	return decoded.TargetRequestID, true
}

func cancelAccepted(requestID, targetRequestID string) Response {
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       requestID,
		Result: success(map[string]interface{}{
			"type": "cancel_accepted",
			"data": map[string]interface{}{"target_request_id": targetRequestID},
		}),
	}
}

func cancelTooLate(requestID string) Response {
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       requestID,
		Result:          failure("invalid_state_transition", "operation already completed", false),
	}
}
