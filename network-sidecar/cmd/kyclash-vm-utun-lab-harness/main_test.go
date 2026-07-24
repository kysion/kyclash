//go:build darwin && kyclash_utun

package main

import (
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

func validFacts() runtimeFacts {
	return runtimeFacts{
		goos:              "darwin",
		goarch:            "arm64",
		effectiveUID:      0,
		model:             "VirtualMac2,1\n",
		runnerEnvironment: runnerEnvironment,
		confirmation:      vmConfirmation,
		runtimeTarget:     runtimeTarget,
		consoleUID:        501,
	}
}

func TestRuntimeGuardRequiresExactDisposableVM(t *testing.T) {
	if err := validateRuntimeFacts(validFacts()); err != nil {
		t.Fatalf("valid facts rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*runtimeFacts)
	}{
		{"non-root", func(facts *runtimeFacts) { facts.effectiveUID = 501 }},
		{"physical-mac", func(facts *runtimeFacts) { facts.model = "MacBookPro18,3" }},
		{"wrong-architecture", func(facts *runtimeFacts) { facts.goarch = "amd64" }},
		{"wrong-runner", func(facts *runtimeFacts) { facts.runnerEnvironment = "github-actions" }},
		{"wrong-confirmation", func(facts *runtimeFacts) { facts.confirmation = "yes" }},
		{"wrong-target", func(facts *runtimeFacts) { facts.runtimeTarget = "kyclash-macos-lab-base" }},
		{"root-console", func(facts *runtimeFacts) { facts.consoleUID = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := validFacts()
			test.mutate(&facts)
			if err := validateRuntimeFacts(facts); err == nil {
				t.Fatal("invalid runtime facts accepted")
			}
		})
	}
}

func TestHarnessAcceptsNoArgumentsAndUsesFixedRootSocket(t *testing.T) {
	if err := validateArguments(nil); err != nil {
		t.Fatalf("empty arguments rejected: %v", err)
	}
	if err := validateArguments([]string{"--socket", "/tmp/other"}); err == nil {
		t.Fatal("caller-controlled socket accepted")
	}
	if socketPath != "/var/run/net.kysion.kyclash.vm-utun-lab.sock" {
		t.Fatalf("unexpected socket path: %s", socketPath)
	}
}

func TestVMUtunProfileIsFixedAndRouteFreeAtHarnessBoundary(t *testing.T) {
	// The full profile requires live loopback cluster keys/endpoints and is
	// covered by labserver integration tests. These constants are the immutable
	// App/harness identity and fallback boundary.
	if profileID != "lab.vm-utun.actual-child" || siteID != "lab-vm-utun" {
		t.Fatal("unexpected VM-utun profile identity")
	}
	if profile.QUIC == profile.WSS || profile.WSS == profile.TCP {
		t.Fatal("transport identities unexpectedly alias")
	}
}
