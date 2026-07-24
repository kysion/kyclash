package vmexternalpeerlab

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/ipc"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

var errInjected = errors.New("injected backend failure")

type eventLog struct {
	values []string
}

func (log *eventLog) add(value string) {
	log.values = append(log.values, value)
}

type fakePacketBackend struct {
	events        *eventLog
	facts         ipc.TunnelDeviceFacts
	health        ipc.Health
	prepareErr    error
	connectErr    error
	healthErr     error
	disconnectErr error
	stopErr       error
	closeErr      error
}

func (backend *fakePacketBackend) Prepare(
	_ context.Context,
	_ *profile.Profile,
	_ string,
) (ipc.TunnelDeviceFacts, error) {
	backend.events.add("base.prepare")
	return backend.facts, backend.prepareErr
}

func (backend *fakePacketBackend) Connect(
	_ context.Context,
	transport profile.Transport,
	_ profile.NormalizedEndpoint,
) error {
	backend.events.add("base.connect." + string(transport))
	return backend.connectErr
}

func (backend *fakePacketBackend) Health(context.Context) (ipc.Health, error) {
	backend.events.add("base.health")
	return backend.health, backend.healthErr
}

func (backend *fakePacketBackend) Disconnect(context.Context) error {
	backend.events.add("base.disconnect")
	return backend.disconnectErr
}

func (backend *fakePacketBackend) Stop(context.Context) error {
	backend.events.add("base.stop")
	return backend.stopErr
}

func (backend *fakePacketBackend) Close() error {
	backend.events.add("base.close")
	return backend.closeErr
}

type fakeSupervisor struct {
	events   *eventLog
	failures map[SupervisorOperation]error
}

func (supervisor *fakeSupervisor) result(operation SupervisorOperation) error {
	supervisor.events.add("supervisor." + string(operation))
	return supervisor.failures[operation]
}

func (supervisor *fakeSupervisor) PrepareFixture(context.Context) error {
	return supervisor.result(PrepareFixture)
}

func (supervisor *fakeSupervisor) BindTunnel(
	_ context.Context,
	_,
	_,
	_ string,
) error {
	return supervisor.result(BindTunnel)
}

func (supervisor *fakeSupervisor) ApplyRoute(context.Context) error {
	return supervisor.result(ApplyRoute)
}

func (supervisor *fakeSupervisor) VerifyRuntime(context.Context) error {
	return supervisor.result(VerifyRuntime)
}

func (supervisor *fakeSupervisor) DeleteRoute(context.Context) error {
	return supervisor.result(DeleteRoute)
}

func (supervisor *fakeSupervisor) ReleaseRuntime(context.Context) error {
	return supervisor.result(ReleaseRuntime)
}

type fakeEcho struct {
	events  *eventLog
	latency time.Duration
	err     error
}

func (echo *fakeEcho) VerifyEcho(context.Context) (time.Duration, error) {
	echo.events.add("echo.verify")
	return echo.latency, echo.err
}

type fakeSSH struct {
	events        *eventLog
	result        SSHVerification
	err           error
	interfaces    []string
	requireSystem []bool
}

func (ssh *fakeSSH) VerifySSH(_ context.Context, tunnelInterface string, requireSystem bool) (SSHVerification, error) {
	ssh.events.add("ssh.verify")
	ssh.interfaces = append(ssh.interfaces, tunnelInterface)
	ssh.requireSystem = append(ssh.requireSystem, requireSystem)
	return ssh.result, ssh.err
}

type backendFixture struct {
	backend    *Backend
	base       *fakePacketBackend
	supervisor *fakeSupervisor
	echo       *fakeEcho
	ssh        *fakeSSH
	profile    *profile.Profile
	events     *eventLog
}

func newBackendFixture(t *testing.T) backendFixture {
	t.Helper()
	events := &eventLog{}
	base := &fakePacketBackend{
		events: events,
		facts: ipc.TunnelDeviceFacts{
			InterfaceName: "utun7",
			MTU:           profile.TunnelMTU,
			HasIPv4:       true,
			HasIPv6:       false,
			InstanceID:    "instance.external-peer",
			OperationID:   "operation.prepare",
		},
		health: ipc.Health{Reachable: true, LatencyMS: 4},
	}
	supervisor := &fakeSupervisor{events: events, failures: make(map[SupervisorOperation]error)}
	echo := &fakeEcho{events: events, latency: 7 * time.Millisecond}
	ssh := &fakeSSH{
		events: events,
		result: SSHVerification{InProcessVerified: true, SystemVerified: true},
	}
	strict := strictTestProfile()
	backend, err := newBackend(
		base,
		strict,
		"instance.external-peer",
		supervisor,
		echo,
		ssh,
	)
	if err != nil {
		t.Fatal(err)
	}
	return backendFixture{
		backend: backend, base: base, supervisor: supervisor,
		echo: echo, ssh: ssh, profile: strict, events: events,
	}
}

func prepareAndConnect(t *testing.T, fixture backendFixture, transport profile.Transport) {
	t.Helper()
	fixture.base.facts.OperationID = "operation.prepare"
	if _, err := fixture.backend.Prepare(
		context.Background(),
		fixture.profile,
		"operation.prepare",
	); err != nil {
		t.Fatal(err)
	}
	endpoint, err := fixture.profile.Endpoint(transport)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.backend.Connect(context.Background(), transport, endpoint); err != nil {
		t.Fatal(err)
	}
}

func TestBackendPreservesRouteAcrossFallbackAndReturnsAllProofs(t *testing.T) {
	fixture := newBackendFixture(t)
	prepareAndConnect(t, fixture, profile.QUIC)
	health, err := fixture.backend.Health(context.Background())
	if err != nil || !health.Reachable {
		t.Fatalf("unexpected health result: %#v %v", health, err)
	}
	reachability, err := fixture.backend.PrivateReachability(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reachability.Reachable || reachability.LatencyMS != 7 ||
		reachability.MihomoCoexisting == nil || !*reachability.MihomoCoexisting ||
		reachability.OverlaySSHVerified == nil || !*reachability.OverlaySSHVerified ||
		reachability.SystemSSHVerified == nil || *reachability.SystemSSHVerified {
		t.Fatalf("unexpected private reachability proof: %#v", reachability)
	}
	if !slices.Equal(fixture.ssh.interfaces, []string{"utun7"}) {
		t.Fatalf("SSH proof was not bound to the owned utun: %v", fixture.ssh.interfaces)
	}
	if !slices.Equal(fixture.ssh.requireSystem, []bool{false}) {
		t.Fatalf("system SSH ran before final TCP: %v", fixture.ssh.requireSystem)
	}
	if err := fixture.backend.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	wss, err := fixture.profile.Endpoint(profile.WSS)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.backend.Connect(context.Background(), profile.WSS, wss); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.backend.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.backend.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.backend.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.backend.Close(); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"supervisor.prepare_fixture",
		"base.prepare",
		"supervisor.bind_tunnel",
		"base.connect.quic",
		"base.health",
		"supervisor.apply_route",
		"supervisor.verify_runtime",
		"echo.verify",
		"ssh.verify",
		"supervisor.verify_runtime",
		"base.disconnect",
		"base.connect.wss",
		"base.health",
		"base.disconnect",
		"supervisor.delete_route",
		"base.stop",
		"base.close",
		"supervisor.release_runtime",
	}
	if !slices.Equal(fixture.events.values, expected) {
		t.Fatalf("unexpected lifecycle order:\n got %v\nwant %v", fixture.events.values, expected)
	}
}

func TestHealthMustBeReachableBeforeRouteApply(t *testing.T) {
	fixture := newBackendFixture(t)
	fixture.base.health = ipc.Health{Reachable: false, LossPercent: 100}
	prepareAndConnect(t, fixture, profile.QUIC)
	health, err := fixture.backend.Health(context.Background())
	if err != nil || health.Reachable {
		t.Fatalf("unexpected unreachable health result: %#v %v", health, err)
	}
	if slices.Contains(fixture.events.values, "supervisor.apply_route") {
		t.Fatal("route was applied before carrier health")
	}
	if _, err := fixture.backend.PrivateReachability(context.Background()); !errors.Is(err, ErrInvalidBackendState) {
		t.Fatalf("private reachability ran without an applied route: %v", err)
	}
	if err := fixture.backend.Close(); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(fixture.events.values, "supervisor.delete_route") {
		t.Fatal("cleanup deleted a route transaction that never started")
	}
}

func TestOnlySteadyStateDeadlineBecomesTypedUnreachableHealth(t *testing.T) {
	startup := newBackendFixture(t)
	startup.base.healthErr = context.DeadlineExceeded
	prepareAndConnect(t, startup, profile.QUIC)
	if _, err := startup.backend.Health(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("startup deadline was incorrectly normalized: %v", err)
	}
	if slices.Contains(startup.events.values, "supervisor.apply_route") {
		t.Fatal("startup deadline installed the private route")
	}

	steady := newBackendFixture(t)
	prepareAndConnect(t, steady, profile.QUIC)
	if health, err := steady.backend.Health(context.Background()); err != nil || !health.Reachable {
		t.Fatalf("initial healthy sample failed: %#v %v", health, err)
	}
	steady.base.healthErr = context.DeadlineExceeded
	health, err := steady.backend.Health(context.Background())
	if err != nil || health.Reachable || health.LossPercent != 100 {
		t.Fatalf("steady deadline did not become typed loss: %#v %v", health, err)
	}
	steady.base.healthErr = errInjected
	if _, err := steady.backend.Health(context.Background()); !errors.Is(err, errInjected) {
		t.Fatalf("unrelated steady error was normalized: %v", err)
	}
}

func TestApplyFailureStillRequiresRouteDeleteBeforeBaseClose(t *testing.T) {
	fixture := newBackendFixture(t)
	fixture.supervisor.failures[ApplyRoute] = errInjected
	prepareAndConnect(t, fixture, profile.QUIC)
	if _, err := fixture.backend.Health(context.Background()); !errors.Is(err, errInjected) {
		t.Fatalf("expected apply failure, got %v", err)
	}
	delete(fixture.supervisor.failures, ApplyRoute)
	if err := fixture.backend.Close(); err != nil {
		t.Fatal(err)
	}
	deleteIndex := slices.Index(fixture.events.values, "supervisor.delete_route")
	closeIndex := slices.Index(fixture.events.values, "base.close")
	releaseIndex := slices.Index(fixture.events.values, "supervisor.release_runtime")
	if deleteIndex < 0 || closeIndex <= deleteIndex || releaseIndex <= closeIndex {
		t.Fatalf("unsafe cleanup order after apply failure: %v", fixture.events.values)
	}
}

func TestDeleteFailurePreservesBaseUntilRetry(t *testing.T) {
	fixture := newBackendFixture(t)
	prepareAndConnect(t, fixture, profile.QUIC)
	if _, err := fixture.backend.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.supervisor.failures[DeleteRoute] = errInjected
	if err := fixture.backend.Close(); !errors.Is(err, errInjected) {
		t.Fatalf("expected route-delete failure, got %v", err)
	}
	if slices.Contains(fixture.events.values, "base.close") ||
		slices.Contains(fixture.events.values, "supervisor.release_runtime") {
		t.Fatalf("ambiguous route deletion released the backend: %v", fixture.events.values)
	}
	if fixture.backend.closed || !fixture.backend.routeOwned {
		t.Fatal("ambiguous route deletion discarded cleanup ownership")
	}

	delete(fixture.supervisor.failures, DeleteRoute)
	if err := fixture.backend.Close(); err != nil {
		t.Fatal(err)
	}
	expectedTail := []string{
		"supervisor.delete_route",
		"supervisor.delete_route",
		"base.close",
		"supervisor.release_runtime",
	}
	if len(fixture.events.values) < len(expectedTail) ||
		!slices.Equal(fixture.events.values[len(fixture.events.values)-len(expectedTail):], expectedTail) {
		t.Fatalf("retry did not preserve delete-before-close order: %v", fixture.events.values)
	}
}

func TestPrivateReachabilityFailsClosedAtEachProofBoundary(t *testing.T) {
	tests := []struct {
		name      string
		transport profile.Transport
		configure func(backendFixture)
		wantTail  []string
	}{
		{
			name: "runtime before echo",
			configure: func(fixture backendFixture) {
				fixture.supervisor.failures[VerifyRuntime] = errInjected
			},
			wantTail: []string{"supervisor.verify_runtime"},
		},
		{
			name: "fixed echo before SSH",
			configure: func(fixture backendFixture) {
				fixture.echo.err = errInjected
			},
			wantTail: []string{"supervisor.verify_runtime", "echo.verify"},
		},
		{
			name:      "both SSH proofs required on final TCP",
			transport: profile.TCP,
			configure: func(fixture backendFixture) {
				fixture.ssh.result.SystemVerified = false
			},
			wantTail: []string{"supervisor.verify_runtime", "echo.verify", "ssh.verify"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBackendFixture(t)
			transport := test.transport
			if transport == "" {
				transport = profile.QUIC
			}
			prepareAndConnect(t, fixture, transport)
			if _, err := fixture.backend.Health(context.Background()); err != nil {
				t.Fatal(err)
			}
			start := len(fixture.events.values)
			test.configure(fixture)
			result, err := fixture.backend.PrivateReachability(context.Background())
			if err == nil || result != (ipc.PrivateReachability{}) {
				t.Fatalf("proof failure returned success: %#v %v", result, err)
			}
			if !slices.Equal(fixture.events.values[start:], test.wantTail) {
				t.Fatalf("proof boundary changed: got %v want %v", fixture.events.values[start:], test.wantTail)
			}
		})
	}
}

func TestPrepareBindFailureClosesBaseBeforeFixtureRelease(t *testing.T) {
	fixture := newBackendFixture(t)
	fixture.supervisor.failures[BindTunnel] = errInjected
	_, err := fixture.backend.Prepare(
		context.Background(),
		fixture.profile,
		"operation.prepare",
	)
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected bind failure, got %v", err)
	}
	expected := []string{
		"supervisor.prepare_fixture",
		"base.prepare",
		"supervisor.bind_tunnel",
		"base.close",
		"supervisor.release_runtime",
	}
	if !slices.Equal(fixture.events.values, expected) || !fixture.backend.closed {
		t.Fatalf("prepare failure did not clean up: %v", fixture.events.values)
	}
}

func TestPrepareFailureDoesNotReleaseFixtureWhenBaseCloseFails(t *testing.T) {
	fixture := newBackendFixture(t)
	fixture.supervisor.failures[BindTunnel] = errInjected
	fixture.base.closeErr = errInjected
	if _, err := fixture.backend.Prepare(
		context.Background(),
		fixture.profile,
		"operation.prepare",
	); !errors.Is(err, errInjected) {
		t.Fatalf("expected prepare cleanup failure, got %v", err)
	}
	if slices.Contains(fixture.events.values, "supervisor.release_runtime") {
		t.Fatalf("fixture released while base close was ambiguous: %v", fixture.events.values)
	}
	fixture.base.closeErr = nil
	delete(fixture.supervisor.failures, BindTunnel)
	if err := fixture.backend.Close(); err != nil {
		t.Fatal(err)
	}
	expectedTail := []string{"base.close", "base.close", "supervisor.release_runtime"}
	if len(fixture.events.values) < len(expectedTail) ||
		!slices.Equal(fixture.events.values[len(fixture.events.values)-len(expectedTail):], expectedTail) {
		t.Fatalf("cleanup retry order changed: %v", fixture.events.values)
	}
}

func TestStrictProfileAndEndpointCannotBeSubstituted(t *testing.T) {
	fixture := newBackendFixture(t)
	substitute := strictTestProfile()
	substitute.Transports.Endpoints[0].URL = "https://192.168.64.3:21999"
	if _, err := fixture.backend.Prepare(
		context.Background(),
		substitute,
		"operation.prepare",
	); !errors.Is(err, ErrInvalidBackendState) {
		t.Fatalf("accepted substituted profile: %v", err)
	}
	if len(fixture.events.values) != 0 {
		t.Fatalf("profile substitution reached runtime authority: %v", fixture.events.values)
	}

	prepareAndConnectCandidate := newBackendFixture(t)
	if _, err := prepareAndConnectCandidate.backend.Prepare(
		context.Background(),
		prepareAndConnectCandidate.profile,
		"operation.prepare",
	); err != nil {
		t.Fatal(err)
	}
	endpoint, err := prepareAndConnectCandidate.profile.Endpoint(profile.QUIC)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Address = "192.168.64.3:21999"
	if err := prepareAndConnectCandidate.backend.Connect(
		context.Background(),
		profile.QUIC,
		endpoint,
	); !errors.Is(err, ErrInvalidBackendState) {
		t.Fatalf("accepted substituted endpoint: %v", err)
	}
	if slices.Contains(prepareAndConnectCandidate.events.values, "base.connect.quic") {
		t.Fatal("endpoint substitution reached the carrier")
	}
}

func TestStrictProfileRejectsUnsafeExternalShape(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*profile.Profile)
	}{
		{
			name: "loopback endpoint",
			mutate: func(value *profile.Profile) {
				for index := range value.Transports.Endpoints {
					switch value.Transports.Endpoints[index].Transport {
					case profile.QUIC:
						value.Transports.Endpoints[index].URL = "https://127.0.0.1:21001"
					case profile.WSS:
						value.Transports.Endpoints[index].URL = "wss://127.0.0.1:21002/kynp"
					case profile.TCP:
						value.Transports.Endpoints[index].URL = "tcp://127.0.0.1:21003"
					}
				}
			},
		},
		{
			name: "wrong WSS path",
			mutate: func(value *profile.Profile) {
				value.Transports.Endpoints[1].URL = "wss://192.168.64.3:21002/other"
			},
		},
		{
			name: "non-random low port",
			mutate: func(value *profile.Profile) {
				value.Transports.Endpoints[0].URL = "https://192.168.64.3:443"
			},
		},
		{
			name: "duplicate carrier port",
			mutate: func(value *profile.Profile) {
				value.Transports.Endpoints[2].URL = "tcp://192.168.64.3:21002"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := strictTestProfile()
			test.mutate(value)
			fixture := newBackendFixture(t)
			backend, err := newBackend(
				fixture.base,
				value,
				"instance.external-peer",
				fixture.supervisor,
				fixture.echo,
				fixture.ssh,
			)
			if backend != nil || !errors.Is(err, ErrInvalidBackendState) {
				t.Fatalf("accepted unsafe external profile: backend=%v err=%v", backend, err)
			}
		})
	}
}

func strictTestProfile() *profile.Profile {
	wireGuardKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return &profile.Profile{
		SchemaVersion: profile.SchemaVersion,
		ProfileID:     ProfileID,
		ControlPlane:  "https://control.external-peer.test",
		IdentityRef:   "keychain:net.kysion.kyclash.test",
		Site: profile.Site{
			ID:           SiteID,
			DisplayName:  "External peer lab",
			PrivateCIDRs: []string{PrivateCIDR},
		},
		Tunnel: profile.Tunnel{
			LocalAddresses:   []string{ClientCIDR},
			PeerPublicKey:    wireGuardKey,
			KeepaliveSeconds: 25,
		},
		Transports: profile.Transports{
			Primary:   profile.QUIC,
			Fallbacks: []profile.Transport{profile.WSS, profile.TCP},
			Endpoints: []profile.Endpoint{
				{Transport: profile.QUIC, URL: "https://192.168.64.3:21001"},
				{Transport: profile.WSS, URL: "wss://192.168.64.3:21002/kynp"},
				{Transport: profile.TCP, URL: "tcp://192.168.64.3:21003"},
			},
		},
		Policy: profile.Policy{
			ConnectTimeoutSeconds: 10,
			HealthIntervalSeconds: 5,
			FallbackThreshold:     1,
		},
	}
}
