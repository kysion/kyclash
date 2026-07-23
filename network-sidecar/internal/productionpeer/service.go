package productionpeer

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

var (
	ErrInvalidState          = errors.New("invalid production peer state")
	ErrIdentityUnavailable   = errors.New("production peer identity unavailable")
	ErrForwardingUnavailable = errors.New("production peer forwarding unavailable")
	ErrCarrierUnavailable    = errors.New("production peer carrier unavailable")
	ErrCleanupFailed         = errors.New("production peer cleanup failed")
)

type State string

const (
	StateStopped      State = "stopped"
	StateStarting     State = "starting"
	StateReady        State = "ready"
	StateStopping     State = "stopping"
	StateFailedClosed State = "failed_closed"
)

type Status struct {
	PeerID       string `json:"peer_id"`
	DeploymentID string `json:"deployment_id"`
	State        State  `json:"state"`
}

type IdentityFacts struct {
	TLSServerName                string
	LocalTLSCertificateSHA256    string
	WireGuardPublicKey           string
	LoadedFromSystemdCredentials bool
}

type IdentityLease interface {
	Facts() IdentityFacts
	Close(context.Context) error
}

type IdentityProvider interface {
	Acquire(context.Context, Config) (IdentityLease, error)
}

type ForwardingFacts struct {
	TunnelInterface       string
	SiteInterface         string
	PrivateCIDRs          []string
	ClientTunnelAddresses []string
	ReturnPathMode        string
}

type ForwardingLease interface {
	Facts() ForwardingFacts
	Done() <-chan error
	Close(context.Context) error
}

type Forwarder interface {
	Prepare(context.Context, Config, IdentityLease) (ForwardingLease, error)
}

type CarrierFacts struct {
	Transports     []profile.Transport
	Binds          []string
	URLs           []string
	ActiveCarriers uint8
}

type CarrierLease interface {
	Facts() CarrierFacts
	Done() <-chan error
	Close(context.Context) error
}

type CarrierFactory interface {
	Open(context.Context, Config, IdentityLease, ForwardingLease) (CarrierLease, error)
}

type Dependencies struct {
	Identities IdentityProvider
	Forwarder  Forwarder
	Carriers   CarrierFactory
}

// Service is the source-level orchestration contract for the Linux peer. It
// deliberately cannot create any production resource without all three typed
// dependencies. The command skeleton does not provide them yet, so live mode
// remains unavailable rather than silently falling back to a lab peer.
type Service struct {
	operationMu  sync.Mutex
	mu           sync.RWMutex
	config       Config
	dependencies Dependencies
	state        State
	identity     IdentityLease
	forwarding   ForwardingLease
	carriers     CarrierLease
}

func NewService(config Config, dependencies Dependencies) (*Service, error) {
	if config.Validate() != nil ||
		dependencies.Identities == nil ||
		dependencies.Forwarder == nil ||
		dependencies.Carriers == nil {
		return nil, ErrInvalidConfig
	}
	return &Service{
		config:       config,
		dependencies: dependencies,
		state:        StateStopped,
	}, nil
}

func (service *Service) Status() Status {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return Status{
		PeerID:       service.config.PeerID,
		DeploymentID: service.config.DeploymentID,
		State:        service.state,
	}
}

func (service *Service) Start(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidState
	}
	service.operationMu.Lock()
	defer service.operationMu.Unlock()

	service.mu.Lock()
	if service.state != StateStopped ||
		service.identity != nil ||
		service.forwarding != nil ||
		service.carriers != nil {
		service.mu.Unlock()
		return ErrInvalidState
	}
	service.state = StateStarting
	service.mu.Unlock()

	identity, err := service.dependencies.Identities.Acquire(ctx, service.config)
	if err != nil || identity == nil || !identity.Facts().validFor(service.config) {
		service.failStart(identity, nil, nil)
		return ErrIdentityUnavailable
	}
	if ctx.Err() != nil {
		service.failStart(identity, nil, nil)
		return ErrIdentityUnavailable
	}

	forwarding, err := service.dependencies.Forwarder.Prepare(ctx, service.config, identity)
	if err != nil || forwarding == nil || !forwarding.Facts().validFor(service.config) {
		service.failStart(identity, forwarding, nil)
		return ErrForwardingUnavailable
	}
	if ctx.Err() != nil {
		service.failStart(identity, forwarding, nil)
		return ErrForwardingUnavailable
	}

	carriers, err := service.dependencies.Carriers.Open(ctx, service.config, identity, forwarding)
	if err != nil || carriers == nil || !carriers.Facts().validFor(service.config) {
		service.failStart(identity, forwarding, carriers)
		return ErrCarrierUnavailable
	}
	if ctx.Err() != nil {
		service.failStart(identity, forwarding, carriers)
		return ErrCarrierUnavailable
	}

	service.mu.Lock()
	service.identity = identity
	service.forwarding = forwarding
	service.carriers = carriers
	service.state = StateReady
	service.mu.Unlock()
	return nil
}

func (service *Service) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidState
	}
	if err := service.Start(ctx); err != nil {
		return err
	}
	service.mu.RLock()
	forwarding := service.forwarding
	carriers := service.carriers
	service.mu.RUnlock()
	var result error
	select {
	case <-ctx.Done():
	case <-forwarding.Done():
		result = ErrForwardingUnavailable
	case <-carriers.Done():
		result = ErrCarrierUnavailable
	}
	if err := service.Stop(context.Background()); err != nil {
		return err
	}
	return result
}

func (service *Service) Stop(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidState
	}
	service.operationMu.Lock()
	defer service.operationMu.Unlock()

	service.mu.Lock()
	if service.state == StateStopped &&
		service.identity == nil &&
		service.forwarding == nil &&
		service.carriers == nil {
		service.mu.Unlock()
		return nil
	}
	// FailedClosed is terminal for this process. Once cleanup has failed or a
	// start invariant was violated, no in-process retry may relabel unknown
	// kernel/listener state as stopped.
	if service.state == StateFailedClosed {
		service.mu.Unlock()
		return ErrInvalidState
	}
	if service.state != StateReady {
		service.mu.Unlock()
		return ErrInvalidState
	}
	service.state = StateStopping
	identity := service.identity
	forwarding := service.forwarding
	carriers := service.carriers
	service.identity = nil
	service.forwarding = nil
	service.carriers = nil
	service.mu.Unlock()

	cleanupContext, cancelCleanup := service.cleanupContext(ctx)
	defer cancelCleanup()
	cleanupFailed := closeLeases(cleanupContext, identity, forwarding, carriers)
	service.mu.Lock()
	if cleanupFailed {
		service.state = StateFailedClosed
	} else {
		service.state = StateStopped
	}
	service.mu.Unlock()
	if cleanupFailed {
		return ErrCleanupFailed
	}
	return nil
}

func (service *Service) failStart(identity IdentityLease, forwarding ForwardingLease, carriers CarrierLease) {
	cleanupContext, cancelCleanup := service.cleanupContext(context.Background())
	defer cancelCleanup()
	cleanupFailed := closeLeases(cleanupContext, identity, forwarding, carriers)
	service.mu.Lock()
	service.identity = nil
	service.forwarding = nil
	service.carriers = nil
	service.state = StateFailedClosed
	service.mu.Unlock()
	_ = cleanupFailed
}

func (service *Service) cleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	timeout := time.Duration(service.config.Policy.ShutdownGraceSeconds) * time.Second
	if deadline, ok := parent.Deadline(); ok && time.Until(deadline) < timeout {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(context.Background(), timeout)
}

func closeLeases(ctx context.Context, identity IdentityLease, forwarding ForwardingLease, carriers CarrierLease) bool {
	failed := false
	if carriers != nil && carriers.Close(ctx) != nil {
		failed = true
	}
	if forwarding != nil && forwarding.Close(ctx) != nil {
		failed = true
	}
	if identity != nil && identity.Close(ctx) != nil {
		failed = true
	}
	return failed
}

func (facts IdentityFacts) validFor(config Config) bool {
	return facts.TLSServerName == config.TLS.ServerName &&
		facts.LocalTLSCertificateSHA256 == config.TLS.LocalCertificateSHA256 &&
		facts.WireGuardPublicKey == config.WireGuard.ServerPublicKeyBase64 &&
		facts.LoadedFromSystemdCredentials
}

func (facts ForwardingFacts) validFor(config Config) bool {
	return facts.TunnelInterface == config.Forwarding.TunnelInterface &&
		facts.SiteInterface == config.Forwarding.SiteInterface &&
		slices.Equal(facts.PrivateCIDRs, config.Forwarding.PrivateCIDRs) &&
		slices.Equal(facts.ClientTunnelAddresses, allClientTunnelAddresses(config.WireGuard)) &&
		facts.ReturnPathMode == config.Forwarding.ReturnPath.Mode
}

func (facts CarrierFacts) validFor(config Config) bool {
	if facts.ActiveCarriers != 0 ||
		len(facts.Transports) != len(config.Listeners) ||
		len(facts.Binds) != len(config.Listeners) ||
		len(facts.URLs) != len(config.Listeners) {
		return false
	}
	for index, listener := range config.Listeners {
		if facts.Transports[index] != listener.Transport ||
			facts.Binds[index] != listener.Bind ||
			facts.URLs[index] != listener.URL {
			return false
		}
	}
	return true
}
