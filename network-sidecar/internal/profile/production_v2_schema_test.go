package profile

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestProductionProfileV2SchemaPinsTheMachineContract(t *testing.T) {
	encoded, err := os.ReadFile("../../../schemas/kyclash-network-production-v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(encoded, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["additionalProperties"] != false {
		t.Fatal("production profile schema permits unknown root fields")
	}
	properties := productionSchemaObject(t, schema["properties"])
	controlPlane := productionSchemaObject(t, properties["control_plane"])
	const controlPlanePattern = `^https://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?=[a-z0-9-]*[a-z][a-z0-9-]*(?::|/|$))[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::(?:[1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?(?:/[A-Za-z0-9._~!$&'()*+,;=:@/-]*)?$`
	if controlPlane["pattern"] != controlPlanePattern {
		t.Fatal("production schema does not pin the ASCII/lone-surrogate control-plane surface")
	}
	if productionSchemaObject(t, properties["schema_version"])["const"] != float64(ProductionSchemaVersionV2) ||
		productionSchemaObject(t, properties["carrier_auth_version"])["const"] != float64(ProductionCarrierAuthVersionV1) {
		t.Fatal("production schema does not pin profile/auth versions")
	}
	required := productionSchemaStrings(t, schema["required"])
	for _, field := range []string{
		"schema_version",
		"carrier_auth_version",
		"profile_id",
		"control_plane",
		"identity_ref",
		"site",
		"tunnel",
		"transports",
		"policy",
	} {
		if !productionSchemaContains(required, field) {
			t.Fatalf("production schema does not require %q", field)
		}
	}
	site := productionSchemaObject(t, properties["site"])
	siteProperties := productionSchemaObject(t, site["properties"])
	displayName := productionSchemaObject(t, siteProperties["display_name"])
	const displayNamePattern = `^(?![\s\S]*[\uD800-\uDFFF])[^\u0009-\u000D\u0020\u0085\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]([\s\S]*[^\u0009-\u000D\u0020\u0085\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000])?$`
	if displayName["maxLength"] != float64(128) ||
		displayName["pattern"] != displayNamePattern {
		t.Fatal("production schema does not pin the display-name boundary")
	}

	tunnel := productionSchemaObject(t, properties["tunnel"])
	tunnelProperties := productionSchemaObject(t, tunnel["properties"])
	if !productionSchemaContains(productionSchemaStrings(t, tunnel["required"]), "local_public_key") {
		t.Fatal("production schema does not require the local WireGuard public key")
	}
	if _, exists := tunnelProperties["mtu"]; exists {
		t.Fatal("MTU must remain a code-level pair invariant, not a profile JSON field")
	}
	transports := productionSchemaObject(t, properties["transports"])
	transportProperties := productionSchemaObject(t, transports["properties"])
	if _, exists := transportProperties["quic_alpn"]; exists {
		t.Fatal("QUIC ALPN must remain a code-level pair invariant, not a profile JSON field")
	}
	fallbacks := productionSchemaObject(t, transportProperties["fallbacks"])
	fallbackItems := productionSchemaArray(t, fallbacks["prefixItems"])
	if len(fallbackItems) != 2 ||
		productionSchemaObject(t, fallbackItems[0])["const"] != string(WSS) ||
		productionSchemaObject(t, fallbackItems[1])["const"] != string(TCP) ||
		fallbacks["items"] != false {
		t.Fatal("production schema does not pin exact WSS to TCP fallback order")
	}
	endpoints := productionSchemaObject(t, transportProperties["endpoints"])
	endpointItems := productionSchemaArray(t, endpoints["prefixItems"])
	if len(endpointItems) != 3 ||
		productionSchemaObject(t, endpointItems[0])["$ref"] != "#/$defs/quic_endpoint" ||
		productionSchemaObject(t, endpointItems[1])["$ref"] != "#/$defs/wss_endpoint" ||
		productionSchemaObject(t, endpointItems[2])["$ref"] != "#/$defs/tcp_endpoint" ||
		endpoints["items"] != false {
		t.Fatal("production schema does not pin exact QUIC to WSS to TCP endpoint order")
	}
	definitions := productionSchemaObject(t, schema["$defs"])
	publicKey := productionSchemaObject(t, definitions["wireguard_public_key"])
	publicKeyPattern := publicKey["pattern"]
	if publicKeyPattern != "^[A-Za-z0-9+/]{41}[A-HQ-Xg-nw-z0-3][AEIMQUYcgkosw048]=$" {
		t.Fatalf("unexpected canonical WireGuard public-key pattern: %v", publicKeyPattern)
	}
	fieldAliases := productionSchemaStrings(
		t,
		productionSchemaObject(t, publicKey["not"])["enum"],
	)
	if len(fieldAliases) != 19 ||
		!productionSchemaContains(fieldAliases, "9v///////////////////////////////////////38=") {
		t.Fatal("production schema does not reject every noncanonical X25519 field alias")
	}
	privatePrefixes := productionSchemaObject(t, definitions["private_prefixes"])
	if privatePrefixes["maxItems"] != float64(MaxProductionProfileV2PrivateCIDRs) {
		t.Fatal("production schema does not pin private-CIDR count")
	}
	wssDefinition := productionSchemaObject(t, definitions["wss_endpoint"])
	wssAllOf := productionSchemaArray(t, wssDefinition["allOf"])
	wssProperties := productionSchemaObject(t, productionSchemaObject(t, wssAllOf[1])["properties"])
	wssURL := productionSchemaObject(t, wssProperties["url"])
	if pattern, _ := wssURL["pattern"].(string); !bytes.Contains([]byte(pattern), []byte("/kynp$")) {
		t.Fatalf("production schema does not pin the WSS path: %v", wssURL["pattern"])
	}
}

func TestProductionProfileV2DisplayNameSchemaECMAScriptUnicodeCorpus(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required to execute the JSON Schema ECMAScript Unicode corpus")
	}
	encoded, err := os.ReadFile("../../../schemas/kyclash-network-production-v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(encoded, &schema); err != nil {
		t.Fatal(err)
	}
	properties := productionSchemaObject(t, schema["properties"])
	site := productionSchemaObject(t, properties["site"])
	siteProperties := productionSchemaObject(t, site["properties"])
	displayName := productionSchemaObject(t, siteProperties["display_name"])
	pattern, ok := displayName["pattern"].(string)
	if !ok {
		t.Fatal("display-name schema pattern is not a string")
	}
	const script = `
const pattern = new RegExp(process.argv[1], "u");
const high = String.fromCharCode(0xD800);
const low = String.fromCharCode(0xDC00);
const emojiFromPair = String.fromCharCode(0xD83D, 0xDE00);
const accepts = (value) =>
  [...value].length >= 1 &&
  [...value].length <= 128 &&
  pattern.test(value);
for (const value of [
  "A",
  "KyClash production pair",
  "生产组网",
  "\uFEFFaccepted",
  "accepted\uFEFF",
  emojiFromPair,
  emojiFromPair.repeat(128),
]) {
  if (!accepts(value)) throw new Error("rejected valid display-name corpus");
}
for (const value of [
  "",
  " leading",
  "trailing ",
  "\tleading",
  "trailing\n",
  "\u0085leading",
  "trailing\u0085",
  high,
  low,
  "a" + high + "b",
  emojiFromPair.repeat(129),
]) {
  if (accepts(value)) throw new Error("accepted invalid display-name corpus");
}
`
	command := exec.Command(node, "-e", script, pattern)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ECMAScript Unicode display-name corpus failed: %v: %s", err, output)
	}
}

func TestProductionProfileV2FixtureMatchesSchemaVersionsAndDecodes(t *testing.T) {
	fixture := productionProfileV2Fixture(t)
	var object map[string]any
	if err := json.Unmarshal(fixture, &object); err != nil {
		t.Fatal(err)
	}
	if object["schema_version"] != float64(ProductionSchemaVersionV2) ||
		object["carrier_auth_version"] != float64(ProductionCarrierAuthVersionV1) {
		t.Fatal("production fixture version drift")
	}
	if _, err := DecodeProductionProfileV2(bytes.NewReader(fixture)); err != nil {
		t.Fatalf("production fixture does not satisfy the Go contract: %v", err)
	}
}

func productionSchemaObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected JSON object, got %T", value)
	}
	return object
}

func productionSchemaArray(t *testing.T, value any) []any {
	t.Helper()
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("expected JSON array, got %T", value)
	}
	return array
}

func productionSchemaStrings(t *testing.T, value any) []string {
	t.Helper()
	raw := productionSchemaArray(t, value)
	result := make([]string, len(raw))
	for index, item := range raw {
		stringValue, ok := item.(string)
		if !ok {
			t.Fatalf("expected string at index %d, got %T", index, item)
		}
		result[index] = stringValue
	}
	return result
}

func productionSchemaContains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
