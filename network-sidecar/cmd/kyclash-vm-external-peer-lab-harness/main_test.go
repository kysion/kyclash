package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
)

func TestHarnessRuntimeAndInvocationAreFixed(t *testing.T) {
	if err := validateArguments([]string{"--profile", "/tmp/profile.json"}); err == nil {
		t.Fatal("accepted caller-controlled arguments")
	}
	valid := runtimeFacts{
		GOOS: "darwin", GOARCH: "arm64", EffectiveUID: 0, ConsoleUID: 501,
		Model: "VirtualMac2,1", WorkingDir: "/", Environment: []string{},
	}
	if err := validateRuntimeFacts(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*runtimeFacts){
		"host":        func(value *runtimeFacts) { value.Model = "Mac15,6" },
		"non-root":    func(value *runtimeFacts) { value.EffectiveUID = 501 },
		"environment": func(value *runtimeFacts) { value.Environment = []string{"PATH=/tmp"} },
		"working-dir": func(value *runtimeFacts) { value.WorkingDir = "/tmp" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := valid
			mutate(&changed)
			if err := validateRuntimeFacts(changed); err == nil {
				t.Fatal("accepted invalid runtime")
			}
		})
	}
	if inheritedAppFD != 3 || inheritedSupervisorFD != 4 {
		t.Fatal("inherited descriptor contract changed")
	}
}

func TestHandshakeContainsOnlyRedactedFixedFacts(t *testing.T) {
	handshake, err := newRedactedHandshake(
		"instance-1234", strings.Repeat("a", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(handshake)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"protocol_version", "instance_id", "auth_proof", "runtime_mode",
		"tunnel_kind", "peer_vm", "mihomo_device", "transport_order",
	}
	actual := make([]string, 0, len(fields))
	for _, key := range expected {
		if _, exists := fields[key]; !exists {
			t.Fatalf("missing redacted handshake key %q", key)
		}
		actual = append(actual, key)
	}
	if len(fields) != len(expected) || !reflect.DeepEqual(actual, expected) {
		t.Fatalf("unexpected handshake authority: %s", raw)
	}
	for _, forbidden := range []string{
		"profile", "endpoint", "port", "certificate", "private_key",
		"public_key", "path", "pid", "route",
	} {
		if strings.Contains(string(raw), `"`+forbidden+`":`) {
			t.Fatalf("handshake leaked forbidden authority %q: %s", forbidden, raw)
		}
	}
	if handshake.PeerVM != vmexternalpeerlab.PeerRuntimeTarget {
		t.Fatal("handshake peer VM changed")
	}
}

func TestRunIDUsesOnlyFreshFixedLengthEntropy(t *testing.T) {
	entropy := make([]byte, 16)
	for index := range entropy {
		entropy[index] = byte(index)
	}
	runID, err := runIDFromEntropy(entropy)
	if err != nil {
		t.Fatal(err)
	}
	if runID != "run-000102030405060708090a0b0c0d0e0f" {
		t.Fatalf("unexpected run ID: %s", runID)
	}
	if _, err := runIDFromEntropy(entropy[:15]); err == nil {
		t.Fatal("accepted short run entropy")
	}
}

func TestTLSCertificateCleanupErasesEveryOwnedByteSlice(t *testing.T) {
	certificateDER := []byte{1, 2, 3}
	ocsp := []byte{4, 5, 6}
	timestamp := []byte{7, 8, 9}
	privateKey := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	for index := range privateKey {
		privateKey[index] = byte(index + 1)
	}
	certificate := tls.Certificate{
		Certificate:                 [][]byte{certificateDER},
		PrivateKey:                  privateKey,
		OCSPStaple:                  ocsp,
		SignedCertificateTimestamps: [][]byte{timestamp},
	}
	clearTLSCertificate(&certificate)
	if !reflect.DeepEqual(certificate, tls.Certificate{}) {
		t.Fatal("TLS certificate retained ownership after cleanup")
	}
	for name, owned := range map[string][]byte{
		"certificate": certificateDER,
		"ocsp":        ocsp,
		"timestamp":   timestamp,
		"private-key": privateKey,
	} {
		for _, value := range owned {
			if value != 0 {
				t.Fatalf("%s bytes were not erased", name)
			}
		}
	}
}

func TestPinnedFactsAndTicketArtifactMustMatchExactly(t *testing.T) {
	client, err := externalpeer.NewCourierVMFacts(
		"client", externalpeer.ClientVMName,
		"11111111-2222-4333-8444-555555555555",
		"SHA256:client",
		"02:00:00:00:00:11",
		mustAddress(t, "192.168.64.11"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePinnedClientFacts(client, client); err != nil {
		t.Fatal(err)
	}
	changed := client
	changed.IPv4[3]++
	if err := validatePinnedClientFacts(changed, client); err == nil {
		t.Fatal("accepted changed client VM facts")
	}

	payload := []byte("harness")
	digest := sha256.Sum256(payload)
	expectation := externalpeer.RunTicketExpectation{
		SchemaVersion: externalpeer.SchemaVersion,
		Files:         make([]externalpeer.ArtifactDigest, len(externalpeer.RunTicketArtifactNames)),
	}
	for index, name := range externalpeer.RunTicketArtifactNames {
		expectation.Files[index] = externalpeer.ArtifactDigest{
			Name: name, Length: 1, SHA256: strings.Repeat("1", 64),
		}
	}
	for index, value := range expectation.Files {
		if value.Name == "client-harness" {
			expectation.Files[index].Length = uint64(len(payload))
			expectation.Files[index].SHA256 = hex.EncodeToString(digest[:])
		}
	}
	if err := matchTicketArtifact(
		expectation, "client-harness", uint64(len(payload)),
		hex.EncodeToString(digest[:]),
	); err != nil {
		t.Fatal(err)
	}
	if err := matchTicketArtifact(
		expectation, "client-harness", uint64(len(payload))+1,
		hex.EncodeToString(digest[:]),
	); err == nil {
		t.Fatal("accepted changed local artifact")
	}
}

func mustAddress(t *testing.T, value string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}
