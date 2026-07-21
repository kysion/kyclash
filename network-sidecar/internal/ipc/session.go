package ipc

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

var ErrBackendUnavailable = errors.New("data-plane backend unavailable")

type Health struct {
	Reachable   bool   `json:"reachable"`
	LatencyMS   uint32 `json:"latency_ms"`
	JitterMS    uint32 `json:"jitter_ms"`
	LossPercent uint8  `json:"loss_percent"`
}

func (health Health) valid() bool {
	return health.LossPercent <= 100
}

type Backend interface {
	Prepare(context.Context, *profile.Profile) error
	Connect(context.Context, profile.Transport, profile.NormalizedEndpoint) error
	Health(context.Context) (Health, error)
	Disconnect(context.Context) error
	Stop(context.Context) error
	Cancel(string) error
	Close() error
}

type contractBackend struct{}

func (contractBackend) Prepare(context.Context, *profile.Profile) error { return nil }
func (contractBackend) Connect(context.Context, profile.Transport, profile.NormalizedEndpoint) error {
	return nil
}
func (contractBackend) Health(context.Context) (Health, error) {
	return Health{Reachable: true}, nil
}
func (contractBackend) Disconnect(context.Context) error { return nil }
func (contractBackend) Stop(context.Context) error       { return nil }
func (contractBackend) Cancel(string) error              { return nil }
func (contractBackend) Close() error                     { return nil }

type session struct {
	profile         *profile.Profile
	backend         Backend
	tunnelPrepared  bool
	activeTransport profile.Transport
	lastError       *string
}

func newSession() *session {
	return newSessionWithBackend(contractBackend{})
}

func newSessionWithBackend(backend Backend) *session {
	return &session{backend: backend}
}

func (current *session) status() Status {
	state := "disconnected"
	if current.tunnelPrepared {
		state = "preparing_tunnel"
	}
	if current.activeTransport == profile.QUIC {
		state = "connected_primary"
	} else if current.activeTransport != "" {
		state = "degraded_fallback"
	}
	var profileID *string
	if current.profile != nil {
		value := current.profile.ProfileID
		profileID = &value
	}
	var transport *string
	if current.activeTransport != "" {
		value := string(current.activeTransport)
		transport = &value
	}
	return Status{State: state, ActiveProfileID: profileID, ActiveTransport: transport, LastError: current.lastError}
}

func decodeProfile(data json.RawMessage) (*profile.Profile, bool) {
	decoded, err := profile.Decode(data)
	return decoded, err == nil
}

func (current *session) backendFailure(response Response) (Response, bool) {
	code := "sidecar_unavailable"
	current.lastError = &code
	response.Result = failure(code, "data-plane operation failed", true)
	return response, false
}
