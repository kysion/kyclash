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

// PrivateReachability is deliberately separate from Health. The VM network
// lab uses this narrow, fixed-scope probe after it has installed its exact
// private /32 route. Production backends do not implement the optional
// interface, so production sidecars reject the corresponding request instead
// of claiming private-route evidence.
type PrivateReachability struct {
	Reachable          bool   `json:"reachable"`
	LatencyMS          uint32 `json:"latency_ms"`
	MihomoCoexisting   *bool  `json:"mihomo_coexisting,omitempty"`
	OverlaySSHVerified *bool  `json:"overlay_ssh_verified,omitempty"`
	SystemSSHVerified  *bool  `json:"system_ssh_verified,omitempty"`
}

type TunnelDeviceFacts struct {
	InterfaceName string `json:"interface_name"`
	MTU           int    `json:"mtu"`
	HasIPv4       bool   `json:"has_ipv4"`
	HasIPv6       bool   `json:"has_ipv6"`
	InstanceID    string `json:"instance_id"`
	OperationID   string `json:"operation_id"`
}

func (health Health) valid() bool {
	return health.LossPercent <= 100
}

func (probe PrivateReachability) valid() bool {
	// A zero latency is valid on the loopback lab; only the bounded integer
	// representation itself is exposed on the wire.
	return true
}

type Backend interface {
	Prepare(context.Context, *profile.Profile, string) (TunnelDeviceFacts, error)
	Connect(context.Context, profile.Transport, profile.NormalizedEndpoint) error
	Health(context.Context) (Health, error)
	Disconnect(context.Context) error
	Stop(context.Context) error
	Close() error
}

// PrivateReachabilityBackend is an optional lab-only extension. It is kept
// out of Backend so existing production implementations cannot accidentally
// claim private-route evidence.
type PrivateReachabilityBackend interface {
	PrivateReachability(context.Context) (PrivateReachability, error)
}

type contractBackend struct{}

func (contractBackend) Prepare(_ context.Context, networkProfile *profile.Profile, operationID string) (TunnelDeviceFacts, error) {
	return TunnelDeviceFacts{
		InterfaceName: "utun0",
		MTU:           profile.TunnelMTU,
		HasIPv4:       true,
		HasIPv6:       true,
		InstanceID:    "contract.instance",
		OperationID:   operationID,
	}, nil
}
func (contractBackend) Connect(context.Context, profile.Transport, profile.NormalizedEndpoint) error {
	return nil
}
func (contractBackend) Health(context.Context) (Health, error) {
	return Health{Reachable: true}, nil
}
func (contractBackend) Disconnect(context.Context) error { return nil }
func (contractBackend) Stop(context.Context) error       { return nil }
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
