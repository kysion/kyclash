package productionpeer

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (log *eventLog) add(event string) {
	log.mu.Lock()
	log.events = append(log.events, event)
	log.mu.Unlock()
}

func (log *eventLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]string(nil), log.events...)
}

type fakeIdentityProvider struct {
	log   *eventLog
	facts IdentityFacts
	err   error
	close error
}

type fakeIdentityLease struct {
	log      *eventLog
	facts    IdentityFacts
	closeErr error
}

func (provider fakeIdentityProvider) Acquire(context.Context, Config) (IdentityLease, error) {
	provider.log.add("identity.acquire")
	if provider.err != nil {
		return nil, provider.err
	}
	return &fakeIdentityLease{log: provider.log, facts: provider.facts, closeErr: provider.close}, nil
}

func (lease *fakeIdentityLease) Facts() IdentityFacts { return lease.facts }
func (lease *fakeIdentityLease) Close(context.Context) error {
	lease.log.add("identity.close")
	return lease.closeErr
}

type fakeForwarder struct {
	log   *eventLog
	facts ForwardingFacts
	err   error
	close error
	done  chan error
}

type fakeForwardingLease struct {
	log      *eventLog
	facts    ForwardingFacts
	closeErr error
	done     chan error
}

func (forwarder fakeForwarder) Prepare(context.Context, Config, IdentityLease) (ForwardingLease, error) {
	forwarder.log.add("forwarder.prepare")
	if forwarder.err != nil {
		return nil, forwarder.err
	}
	return &fakeForwardingLease{
		log:      forwarder.log,
		facts:    forwarder.facts,
		closeErr: forwarder.close,
		done:     forwarder.done,
	}, nil
}

func (lease *fakeForwardingLease) Facts() ForwardingFacts { return lease.facts }
func (lease *fakeForwardingLease) Done() <-chan error     { return lease.done }
func (lease *fakeForwardingLease) Close(context.Context) error {
	lease.log.add("forwarder.close")
	return lease.closeErr
}

type fakeCarrierFactory struct {
	log   *eventLog
	facts CarrierFacts
	err   error
	close error
	done  chan error
}

type fakeCarrierLease struct {
	log      *eventLog
	facts    CarrierFacts
	closeErr error
	done     chan error
}

func (factory fakeCarrierFactory) Open(context.Context, Config, IdentityLease, ForwardingLease) (CarrierLease, error) {
	factory.log.add("carriers.open")
	if factory.err != nil {
		return nil, factory.err
	}
	return &fakeCarrierLease{
		log:      factory.log,
		facts:    factory.facts,
		closeErr: factory.close,
		done:     factory.done,
	}, nil
}

func (lease *fakeCarrierLease) Facts() CarrierFacts { return lease.facts }
func (lease *fakeCarrierLease) Done() <-chan error  { return lease.done }
func (lease *fakeCarrierLease) Close(context.Context) error {
	lease.log.add("carriers.close")
	return lease.closeErr
}

func validDependencies(config Config, log *eventLog) Dependencies {
	transports := make([]profile.Transport, len(config.Listeners))
	binds := make([]string, len(config.Listeners))
	urls := make([]string, len(config.Listeners))
	for index, listener := range config.Listeners {
		transports[index] = listener.Transport
		binds[index] = listener.Bind
		urls[index] = listener.URL
	}
	return Dependencies{
		Identities: fakeIdentityProvider{
			log: log,
			facts: IdentityFacts{
				TLSServerName:                config.TLS.ServerName,
				LocalTLSCertificateSHA256:    config.TLS.LocalCertificateSHA256,
				WireGuardPublicKey:           config.WireGuard.ServerPublicKeyBase64,
				LoadedFromSystemdCredentials: true,
			},
		},
		Forwarder: fakeForwarder{
			log: log,
			facts: ForwardingFacts{
				TunnelInterface:       config.Forwarding.TunnelInterface,
				SiteInterface:         config.Forwarding.SiteInterface,
				PrivateCIDRs:          append([]string(nil), config.Forwarding.PrivateCIDRs...),
				ClientTunnelAddresses: allClientTunnelAddresses(config.WireGuard),
				ReturnPathMode:        config.Forwarding.ReturnPath.Mode,
			},
			done: make(chan error),
		},
		Carriers: fakeCarrierFactory{
			log: log,
			facts: CarrierFacts{
				Transports: transports,
				Binds:      binds,
				URLs:       urls,
			},
			done: make(chan error),
		},
	}
}

func TestServiceStartsOnlyAfterIdentityForwardingAndListenersMatch(t *testing.T) {
	config := validConfig(t)
	log := &eventLog{}
	service, err := NewService(config, validDependencies(config, log))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status := service.Status(); status.State != StateReady ||
		status.PeerID != config.PeerID ||
		status.DeploymentID != config.DeploymentID {
		t.Fatalf("unexpected ready status: %+v", status)
	}
	if got, want := log.snapshot(), []string{
		"identity.acquire",
		"forwarder.prepare",
		"carriers.open",
	}; !slices.Equal(got, want) {
		t.Fatalf("unexpected start order: got %v want %v", got, want)
	}
	if err := service.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := log.snapshot(), []string{
		"identity.acquire",
		"forwarder.prepare",
		"carriers.open",
		"carriers.close",
		"forwarder.close",
		"identity.close",
	}; !slices.Equal(got, want) {
		t.Fatalf("unexpected cleanup order: got %v want %v", got, want)
	}
	if service.Status().State != StateStopped {
		t.Fatalf("unexpected stopped status: %+v", service.Status())
	}
}

func TestIdentityMismatchPreventsForwardingAndListeners(t *testing.T) {
	config := validConfig(t)
	log := &eventLog{}
	dependencies := validDependencies(config, log)
	provider := dependencies.Identities.(fakeIdentityProvider)
	provider.facts.LocalTLSCertificateSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dependencies.Identities = provider
	service, err := NewService(config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("expected identity refusal, got %v", err)
	}
	if got, want := log.snapshot(), []string{"identity.acquire", "identity.close"}; !slices.Equal(got, want) {
		t.Fatalf("unexpected identity-failure order: got %v want %v", got, want)
	}
	if service.Status().State != StateFailedClosed {
		t.Fatalf("unexpected state: %+v", service.Status())
	}
}

func TestIdentityOutsideFixedSystemdCredentialsPreventsForwarding(t *testing.T) {
	config := validConfig(t)
	log := &eventLog{}
	dependencies := validDependencies(config, log)
	provider := dependencies.Identities.(fakeIdentityProvider)
	provider.facts.LoadedFromSystemdCredentials = false
	dependencies.Identities = provider
	service, err := NewService(config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("expected non-systemd identity refusal, got %v", err)
	}
	if got, want := log.snapshot(), []string{"identity.acquire", "identity.close"}; !slices.Equal(got, want) {
		t.Fatalf("unexpected identity-source failure order: got %v want %v", got, want)
	}
}

func TestForwardingMismatchPreventsAnyListener(t *testing.T) {
	config := validConfig(t)
	log := &eventLog{}
	dependencies := validDependencies(config, log)
	forwarder := dependencies.Forwarder.(fakeForwarder)
	forwarder.facts.PrivateCIDRs = []string{"10.0.0.0/8"}
	dependencies.Forwarder = forwarder
	service, err := NewService(config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); !errors.Is(err, ErrForwardingUnavailable) {
		t.Fatalf("expected forwarding refusal, got %v", err)
	}
	if got, want := log.snapshot(), []string{
		"identity.acquire",
		"forwarder.prepare",
		"forwarder.close",
		"identity.close",
	}; !slices.Equal(got, want) {
		t.Fatalf("unexpected forwarding-failure order: got %v want %v", got, want)
	}
}

func TestCarrierFailureClosesForwardingBeforeIdentity(t *testing.T) {
	config := validConfig(t)
	log := &eventLog{}
	dependencies := validDependencies(config, log)
	carriers := dependencies.Carriers.(fakeCarrierFactory)
	carriers.err = errors.New("injected")
	dependencies.Carriers = carriers
	service, err := NewService(config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); !errors.Is(err, ErrCarrierUnavailable) {
		t.Fatalf("expected carrier refusal, got %v", err)
	}
	if got, want := log.snapshot(), []string{
		"identity.acquire",
		"forwarder.prepare",
		"carriers.open",
		"forwarder.close",
		"identity.close",
	}; !slices.Equal(got, want) {
		t.Fatalf("unexpected carrier-failure order: got %v want %v", got, want)
	}
}

func TestRunConvergesOnCarrierFailure(t *testing.T) {
	config := validConfig(t)
	log := &eventLog{}
	dependencies := validDependencies(config, log)
	carriers := dependencies.Carriers.(fakeCarrierFactory)
	close(carriers.done)
	dependencies.Carriers = carriers
	service, err := NewService(config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Run(context.Background()); !errors.Is(err, ErrCarrierUnavailable) {
		t.Fatalf("expected carrier runtime failure, got %v", err)
	}
	if service.Status().State != StateStopped {
		t.Fatalf("runtime failure did not converge to stopped: %+v", service.Status())
	}
	if got := log.snapshot(); !slices.Equal(got[len(got)-3:], []string{
		"carriers.close",
		"forwarder.close",
		"identity.close",
	}) {
		t.Fatalf("runtime failure cleanup was not reverse ordered: %v", got)
	}
}

func TestCleanupFailureRemainsFailedClosed(t *testing.T) {
	config := validConfig(t)
	log := &eventLog{}
	dependencies := validDependencies(config, log)
	forwarder := dependencies.Forwarder.(fakeForwarder)
	forwarder.close = errors.New("injected")
	dependencies.Forwarder = forwarder
	service, err := NewService(config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.Stop(context.Background()); !errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("expected cleanup failure, got %v", err)
	}
	if service.Status().State != StateFailedClosed {
		t.Fatalf("cleanup failure did not remain fail-closed: %+v", service.Status())
	}
	if err := service.Stop(context.Background()); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("terminal failed-closed state was reset in process: %v", err)
	}
	if service.Status().State != StateFailedClosed {
		t.Fatalf("repeat stop relabeled unknown resources: %+v", service.Status())
	}
}
