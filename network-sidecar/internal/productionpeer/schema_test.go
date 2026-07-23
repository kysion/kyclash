package productionpeer

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

const (
	linuxPeerSchemaV1Path = "../../schemas/kyclash-linux-peer-v1.schema.json"
	linuxPeerSchemaV2Path = "../../schemas/kyclash-linux-peer-v2.schema.json"
)

func TestJSONSchemaV2LocksLiveAuthority(t *testing.T) {
	schema := readJSONObject(t, linuxPeerSchemaV2Path)
	if schema["$id"] != "https://github.com/kysion/kyclash/network-sidecar/schemas/kyclash-linux-peer-v2.schema.json" ||
		schema["additionalProperties"] != false {
		t.Fatal("v2 schema identity or closed top-level authority changed")
	}

	required := stringArray(t, schema["required"])
	if !containsString(required, "carrier_auth_version") {
		t.Fatal("carrier_auth_version is not required by the v2 schema")
	}

	properties := object(t, schema["properties"])
	if object(t, properties["schema_version"])["const"] != float64(2) {
		t.Fatal("live schema version must remain exactly 2")
	}
	if object(t, properties["carrier_auth_version"])["const"] != float64(1) {
		t.Fatal("carrier authentication version must remain exactly 1")
	}

	tls := object(t, object(t, properties["tls"])["properties"])
	if object(t, tls["trust_mode"])["const"] != "system_roots" ||
		object(t, tls["minimum_version"])["const"] != "1.3" ||
		object(t, tls["client_authentication"])["const"] != "wireguard_public_key" {
		t.Fatal("v2 TLS authority drifted")
	}
	if _, exists := tls["certificate_sha256"]; exists {
		t.Fatal("ambiguous client-pin field returned to the v2 public schema")
	}
	if _, exists := tls["local_certificate_sha256"]; !exists {
		t.Fatal("peer-local certificate self-check is missing from v2")
	}
	definitions := object(t, schema["$defs"])
	publicKey := object(t, definitions["wireguard_public_key"])
	const canonicalPublicKeyPattern = "^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$"
	if publicKey["pattern"] != canonicalPublicKeyPattern {
		t.Fatal("v2 WireGuard public-key canonical Base64 grammar drifted")
	}
	publicKeyGrammar := regexp.MustCompile(canonicalPublicKeyPattern)
	for _, value := range []string{
		"ERERERERERERERERERERERERERERERERERERERERERE=",
		"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=",
	} {
		if !publicKeyGrammar.MatchString(value) {
			t.Fatalf("canonical WireGuard public key was rejected by schema grammar: %q", value)
		}
	}
	for _, value := range []string{
		"ERERERERERERERERERERERERERERERERERERERERERF=",
		"ERERERERERERERERERERERERERERERERERERERERERE",
		"ERERERERERERERERERERERERERERERERERERERERER\n=",
	} {
		if publicKeyGrammar.MatchString(value) {
			t.Fatalf("noncanonical WireGuard public key was accepted by schema grammar: %q", value)
		}
	}
	serverName := object(t, definitions["server_name"])
	if serverName["pattern"] != "^(?![0-9.]+$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$" {
		t.Fatal("v2 DNS-only canonical server-name grammar drifted")
	}

	wireGuard := object(t, object(t, properties["wireguard"])["properties"])
	clients := object(t, wireGuard["clients"])
	if clients["minItems"] != float64(1) || clients["maxItems"] != float64(1) {
		t.Fatal("v2 must authorize exactly one configured WireGuard client")
	}

	forwarding := object(t, object(t, properties["forwarding"])["properties"])
	if object(t, forwarding["mode"])["const"] != "brokered_linux_tun_fd" ||
		object(t, forwarding["tunnel_interface"])["const"] != "kyclash0" {
		t.Fatal("v2 brokered forwarding authority drifted")
	}
	privateCIDRs := object(t, forwarding["private_cidrs"])
	if privateCIDRs["minItems"] != float64(1) ||
		privateCIDRs["maxItems"] != float64(16) {
		t.Fatal("v2 private CIDR count must remain bounded to 1..16")
	}

	policy := object(t, object(t, properties["policy"])["properties"])
	if object(t, policy["max_active_clients"])["const"] != float64(1) ||
		object(t, policy["max_active_carriers"])["const"] != float64(1) {
		t.Fatal("v2 single-client/carrier concurrency drifted")
	}
	if object(t, policy["shutdown_grace_seconds"])["const"] != float64(10) {
		t.Fatal("v2 shutdown grace must remain exactly 10 seconds")
	}
}

func TestValidV2FixtureMatchesLockedSchemaAuthority(t *testing.T) {
	schema := readJSONObject(t, linuxPeerSchemaV2Path)
	fixture := readJSONObject(t, "testdata/valid-v2.json")

	properties := object(t, schema["properties"])
	for _, required := range stringArray(t, schema["required"]) {
		if _, exists := fixture[required]; !exists {
			t.Fatalf("valid-v2 fixture is missing required field %q", required)
		}
	}
	for field := range fixture {
		if _, exists := properties[field]; !exists {
			t.Fatalf("valid-v2 fixture contains unknown top-level field %q", field)
		}
	}

	if fixture["schema_version"] != float64(2) ||
		fixture["carrier_auth_version"] != float64(1) {
		t.Fatal("valid-v2 fixture has the wrong machine-contract version")
	}
	wireGuard := object(t, fixture["wireguard"])
	if len(array(t, wireGuard["clients"])) != 1 {
		t.Fatal("valid-v2 fixture must contain exactly one client")
	}
	forwarding := object(t, fixture["forwarding"])
	if forwarding["mode"] != "brokered_linux_tun_fd" {
		t.Fatal("valid-v2 fixture must use brokered Linux TUN descriptor handoff")
	}
	privateCIDRs := array(t, forwarding["private_cidrs"])
	if len(privateCIDRs) < 1 || len(privateCIDRs) > 16 {
		t.Fatal("valid-v2 fixture private CIDRs are outside the locked bound")
	}
	policy := object(t, fixture["policy"])
	if policy["shutdown_grace_seconds"] != float64(10) {
		t.Fatal("valid-v2 fixture shutdown grace must remain exactly 10 seconds")
	}
}

func TestSchemaV1RemainsSupersededEvidence(t *testing.T) {
	schema := readJSONObject(t, linuxPeerSchemaV1Path)
	if schema["$id"] != "https://github.com/kysion/kyclash/network-sidecar/schemas/kyclash-linux-peer-v1.schema.json" {
		t.Fatal("superseded v1 schema evidence identity changed")
	}
	properties := object(t, schema["properties"])
	if object(t, properties["schema_version"])["const"] != float64(1) {
		t.Fatal("superseded schema no longer records v1")
	}
	if _, exists := properties["carrier_auth_version"]; exists {
		t.Fatal("historical v1 schema evidence unexpectedly gained carrier auth v1")
	}
	clients := object(t, object(t, object(t, properties["wireguard"])["properties"])["clients"])
	if clients["maxItems"] != float64(32) {
		t.Fatal("superseded v1 authorized-client evidence changed")
	}
	forwarding := object(t, object(t, properties["forwarding"])["properties"])
	if object(t, forwarding["mode"])["const"] != "preprovisioned_linux_tun" {
		t.Fatal("superseded v1 forwarding evidence changed")
	}

	fixture := readJSONObject(t, "testdata/valid-v1.json")
	if fixture["schema_version"] != float64(1) ||
		object(t, fixture["forwarding"])["mode"] != "preprovisioned_linux_tun" {
		t.Fatal("superseded valid-v1 fixture evidence changed")
	}
}

func readJSONObject(t *testing.T, path string) map[string]any {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func object(t *testing.T, value any) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected JSON object, got %T", value)
	}
	return result
}

func array(t *testing.T, value any) []any {
	t.Helper()
	result, ok := value.([]any)
	if !ok {
		t.Fatalf("expected JSON array, got %T", value)
	}
	return result
}

func stringArray(t *testing.T, value any) []string {
	t.Helper()
	values := array(t, value)
	result := make([]string, len(values))
	for index, value := range values {
		stringValue, ok := value.(string)
		if !ok {
			t.Fatalf("expected string array item, got %T", value)
		}
		result[index] = stringValue
	}
	return result
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
