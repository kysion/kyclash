package profile

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func productionProfileV2Fixture(t *testing.T) []byte {
	t.Helper()
	encoded, err := os.ReadFile("../../../schemas/fixtures/network-production-v2.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func validProductionProfileV2(t *testing.T) ProductionProfileV2 {
	t.Helper()
	decoded, err := DecodeProductionProfileV2(bytes.NewReader(productionProfileV2Fixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	return *decoded
}

func TestProductionProfileV2DecodesWithoutChangingV1LabContract(t *testing.T) {
	production := validProductionProfileV2(t)
	if production.SchemaVersion != ProductionSchemaVersionV2 ||
		production.CarrierAuthVersion != ProductionCarrierAuthVersionV1 ||
		ProductionTunnelMTU != 1_420 ||
		ProductionQUICALPN != "kyclash-network/1" ||
		ProductionWSSPath != "/kynp" {
		t.Fatal("production profile did not retain its locked constants")
	}
	for transport, expected := range map[Transport]NormalizedProductionEndpointV2{
		QUIC: {
			Address:    "peer.example.invalid:2443",
			ServerName: "peer.example.invalid",
			Port:       2443,
		},
		WSS: {
			Address:    "peer.example.invalid:2444",
			ServerName: "peer.example.invalid",
			Port:       2444,
		},
		TCP: {
			Address:    "peer.example.invalid:2445",
			ServerName: "peer.example.invalid",
			Port:       2445,
		},
	} {
		endpoint, err := production.Endpoint(transport)
		if err != nil ||
			endpoint.Address != expected.Address ||
			endpoint.ServerName != expected.ServerName ||
			endpoint.Port != expected.Port {
			t.Fatalf("unexpected %s endpoint: %#v %v", transport, endpoint, err)
		}
	}

	v1, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(v1); err != nil {
		t.Fatalf("independent v1 lab profile stopped decoding: %v", err)
	}
	if _, err := DecodeProductionProfileV2(bytes.NewReader(v1)); !errors.Is(err, ErrInvalidProductionProfileV2) {
		t.Fatalf("production decoder accepted v1 lab profile: %v", err)
	}
}

func TestProductionProfileV2RejectsFieldContractMutations(t *testing.T) {
	tests := map[string]func(*ProductionProfileV2){
		"schema-v1": func(candidate *ProductionProfileV2) {
			candidate.SchemaVersion = 1
		},
		"unknown-schema": func(candidate *ProductionProfileV2) {
			candidate.SchemaVersion = 3
		},
		"missing-carrier-auth": func(candidate *ProductionProfileV2) {
			candidate.CarrierAuthVersion = 0
		},
		"unknown-carrier-auth": func(candidate *ProductionProfileV2) {
			candidate.CarrierAuthVersion = 2
		},
		"profile-id": func(candidate *ProductionProfileV2) {
			candidate.ProfileID = "/invalid"
		},
		"control-plane-scheme": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "http://control.example.invalid"
		},
		"control-plane-user": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://user@control.example.invalid"
		},
		"control-plane-query": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://control.example.invalid?token=forbidden"
		},
		"control-plane-port-above-url-range": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://control.example.invalid:65536"
		},
		"control-plane-empty-hostname": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://:443"
		},
		"control-plane-ipv6-zone": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://[fe80::1%25en0]/"
		},
		"control-plane-invalid-ipv4": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://999.999.999.999"
		},
		"control-plane-overflow-ipv4-octet": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://256.1.1.1"
		},
		"control-plane-empty-dns-label": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://1..2"
		},
		"control-plane-ipv4-shorthand": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://127.1"
		},
		"control-plane-uppercase-host": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://Control.Example.Invalid"
		},
		"control-plane-numeric-final-label": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://control.example.999"
		},
		"control-plane-zero-port": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://control.example.invalid:0"
		},
		"control-plane-noncanonical-port": func(candidate *ProductionProfileV2) {
			candidate.ControlPlane = "https://control.example.invalid:0443"
		},
		"identity-ref": func(candidate *ProductionProfileV2) {
			candidate.IdentityRef = "file:/forbidden"
		},
		"site-id": func(candidate *ProductionProfileV2) {
			candidate.Site.ID = ""
		},
		"display-name": func(candidate *ProductionProfileV2) {
			candidate.Site.DisplayName = " trailing "
		},
		"private-cidrs-empty": func(candidate *ProductionProfileV2) {
			candidate.Site.PrivateCIDRs = nil
		},
		"private-cidr-public": func(candidate *ProductionProfileV2) {
			candidate.Site.PrivateCIDRs[0] = "203.0.113.0/24"
		},
		"private-cidr-boundary-crossing": func(candidate *ProductionProfileV2) {
			candidate.Site.PrivateCIDRs[0] = "172.0.0.0/11"
		},
		"private-cidr-noncanonical": func(candidate *ProductionProfileV2) {
			candidate.Site.PrivateCIDRs[0] = "10.127.1.1/16"
		},
		"private-cidr-overlap": func(candidate *ProductionProfileV2) {
			candidate.Site.PrivateCIDRs = append(candidate.Site.PrivateCIDRs, "10.127.1.0/24")
		},
		"private-cidr-family-mismatch": func(candidate *ProductionProfileV2) {
			candidate.Site.PrivateCIDRs = candidate.Site.PrivateCIDRs[:1]
		},
		"local-addresses-empty": func(candidate *ProductionProfileV2) {
			candidate.Tunnel.LocalAddresses = nil
		},
		"local-address-not-host": func(candidate *ProductionProfileV2) {
			candidate.Tunnel.LocalAddresses[0] = "10.255.255.0/24"
		},
		"local-address-public": func(candidate *ProductionProfileV2) {
			candidate.Tunnel.LocalAddresses[0] = "192.0.2.2/32"
		},
		"local-address-duplicate-family": func(candidate *ProductionProfileV2) {
			candidate.Tunnel.LocalAddresses[1] = "10.255.255.3/32"
		},
		"local-address-overlaps-private": func(candidate *ProductionProfileV2) {
			candidate.Tunnel.LocalAddresses[0] = "10.127.0.2/32"
		},
		"keepalive": func(candidate *ProductionProfileV2) {
			candidate.Tunnel.KeepaliveSeconds = 0
		},
		"primary": func(candidate *ProductionProfileV2) {
			candidate.Transports.Primary = WSS
		},
		"fallback-order": func(candidate *ProductionProfileV2) {
			candidate.Transports.Fallbacks[0], candidate.Transports.Fallbacks[1] =
				candidate.Transports.Fallbacks[1], candidate.Transports.Fallbacks[0]
		},
		"fallback-missing": func(candidate *ProductionProfileV2) {
			candidate.Transports.Fallbacks = candidate.Transports.Fallbacks[:1]
		},
		"endpoint-order": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints[0], candidate.Transports.Endpoints[1] =
				candidate.Transports.Endpoints[1], candidate.Transports.Endpoints[0]
		},
		"endpoint-missing": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints = candidate.Transports.Endpoints[:2]
		},
		"endpoint-host-drift": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints[1].URL = "wss://other.example.invalid:2444/kynp"
		},
		"endpoint-duplicate-port": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints[1].URL = "wss://peer.example.invalid:2443/kynp"
		},
		"endpoint-implicit-port": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints[0].URL = "https://peer.example.invalid"
		},
		"endpoint-privileged-port": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints[0].URL = "https://peer.example.invalid:443"
		},
		"wss-path": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints[1].URL = "wss://peer.example.invalid:2444/other"
		},
		"endpoint-query": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints[0].URL = "https://peer.example.invalid:2443?"
		},
		"endpoint-user": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints[0].URL = "https://user@peer.example.invalid:2443"
		},
		"endpoint-ip-host": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints[0].URL = "https://192.0.2.10:2443"
		},
		"endpoint-numeric-dns": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints[0].URL = "https://127.1:2443"
		},
		"endpoint-uppercase-host": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints[0].URL = "https://Peer.Example.Invalid:2443"
		},
		"endpoint-noncanonical-port": func(candidate *ProductionProfileV2) {
			candidate.Transports.Endpoints[0].URL = "https://peer.example.invalid:02443"
		},
		"connect-timeout": func(candidate *ProductionProfileV2) {
			candidate.Policy.ConnectTimeoutSeconds = 0
		},
		"health-interval": func(candidate *ProductionProfileV2) {
			candidate.Policy.HealthIntervalSeconds = 301
		},
		"fallback-threshold": func(candidate *ProductionProfileV2) {
			candidate.Policy.FallbackThreshold = 21
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := validProductionProfileV2(t)
			mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidProductionProfileV2) {
				t.Fatalf("expected production contract refusal, got %v", err)
			}
		})
	}
}

func TestProductionProfileV2RejectsNoncanonicalOrZeroPublicKeys(t *testing.T) {
	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31))
	long := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 33))
	lowOrderOneBytes := make([]byte, 32)
	lowOrderOneBytes[0] = 1
	lowOrderOne := base64.StdEncoding.EncodeToString(lowOrderOneBytes)
	clear(lowOrderOneBytes)
	lowOrderToolchainBytes, err := hex.DecodeString(
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
	)
	if err != nil {
		t.Fatal(err)
	}
	lowOrderToolchain := base64.StdEncoding.EncodeToString(lowOrderToolchainBytes)
	clear(lowOrderToolchainBytes)
	highBitAliasBytes := bytes.Repeat([]byte{0x22}, 32)
	highBitAliasBytes[31] |= 0x80
	highBitAlias := base64.StdEncoding.EncodeToString(highBitAliasBytes)
	clear(highBitAliasBytes)
	fieldAliasBytes := bytes.Repeat([]byte{0xff}, 32)
	fieldAliasBytes[0] = 0xf6
	fieldAliasBytes[31] = 0x7f
	fieldAlias := base64.StdEncoding.EncodeToString(fieldAliasBytes)
	clear(fieldAliasBytes)
	tests := map[string]string{
		"empty":                 "",
		"zero":                  zero,
		"low-order-u1":          lowOrderOne,
		"low-order-toolchain":   lowOrderToolchain,
		"x25519-high-bit-alias": highBitAlias,
		"x25519-field-alias":    fieldAlias,
		"31-bytes":              short,
		"33-bytes":              long,
		"newline":               "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\n",
		"carriage-return":       "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\r",
		"missing-padding":       "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
		"extra-padding":         "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI==",
		"url-safe":              "__________________________________________8=",
		"nonzero-padding-bits":  "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiJ=",
	}
	for name, value := range tests {
		for field, mutate := range map[string]func(*ProductionProfileV2){
			"local": func(candidate *ProductionProfileV2) {
				candidate.Tunnel.LocalPublicKey = value
			},
			"peer": func(candidate *ProductionProfileV2) {
				candidate.Tunnel.PeerPublicKey = value
			},
		} {
			t.Run(name+"/"+field, func(t *testing.T) {
				candidate := validProductionProfileV2(t)
				mutate(&candidate)
				if err := candidate.Validate(); !errors.Is(err, ErrInvalidProductionProfileV2) {
					t.Fatalf("invalid public key was accepted: %v", err)
				}
			})
		}
	}
	t.Run("same-local-and-peer", func(t *testing.T) {
		candidate := validProductionProfileV2(t)
		candidate.Tunnel.LocalPublicKey = candidate.Tunnel.PeerPublicKey
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidProductionProfileV2) {
			t.Fatalf("same client/server key was accepted: %v", err)
		}
	})
}

func TestDecodeProductionProfileV2RejectsDuplicateUnknownTrailingDepthAndSize(t *testing.T) {
	valid := productionProfileV2Fixture(t)
	rootDuplicate := strings.Replace(
		string(valid),
		`"schema_version": 2,`,
		`"schema_version": 2, "schema_version": 2,`,
		1,
	)
	nestedDuplicate := strings.Replace(
		string(valid),
		`"local_public_key":`,
		`"local_public_key": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=", "local_public_key":`,
		1,
	)
	arrayObjectDuplicate := strings.Replace(
		string(valid),
		`"transport": "quic",`,
		`"transport": "quic", "transport": "quic",`,
		1,
	)
	var object map[string]any
	if err := json.Unmarshal(valid, &object); err != nil {
		t.Fatal(err)
	}
	object["private_key"] = strings.Repeat("forbidden", 8)
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	unknownNested := strings.Replace(
		string(valid),
		`"keepalive_seconds": 25`,
		`"keepalive_seconds": 25, "private_key": "forbidden"`,
		1,
	)
	unknownArrayObject := strings.Replace(
		string(valid),
		`"transport": "quic",`,
		`"transport": "quic", "credential": "forbidden",`,
		1,
	)
	missingCarrierAuth := strings.Replace(
		string(valid),
		"  \"carrier_auth_version\": 1,\n",
		"",
		1,
	)
	missingLocalPublicKey := strings.Replace(
		string(valid),
		"    \"local_public_key\": \"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\",\n",
		"",
		1,
	)
	rootCaseAlias := strings.Replace(
		string(valid),
		`"schema_version": 2`,
		`"SCHEMA_VERSION": 2`,
		1,
	)
	rootAliasDuplicate := strings.Replace(
		string(valid),
		`"schema_version": 2`,
		`"schema_version": 1, "SCHEMA_VERSION": 2`,
		1,
	)
	nestedCaseAlias := strings.Replace(
		string(valid),
		`"local_public_key":`,
		`"LOCAL_PUBLIC_KEY":`,
		1,
	)
	nestedAliasDuplicate := strings.Replace(
		string(valid),
		`"local_public_key": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="`,
		`"local_public_key": "ERERERERERERERERERERERERERERERERERERERERERE=", "Local_Public_Key": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="`,
		1,
	)
	arrayObjectCaseAlias := strings.Replace(
		string(valid),
		`"transport": "quic"`,
		`"TRANSPORT": "quic"`,
		1,
	)
	arrayObjectAliasDuplicate := strings.Replace(
		string(valid),
		`"transport": "quic"`,
		`"transport": "tcp", "Transport": "quic"`,
		1,
	)
	deeplyNested := []byte(
		strings.Repeat("[", MaxProductionProfileV2JSONDepth+1) +
			"0" +
			strings.Repeat("]", MaxProductionProfileV2JSONDepth+1),
	)
	tests := map[string][]byte{
		"duplicate-root":         []byte(rootDuplicate),
		"duplicate-nested":       []byte(nestedDuplicate),
		"duplicate-array-object": []byte(arrayObjectDuplicate),
		"unknown-root":           unknown,
		"unknown-nested":         []byte(unknownNested),
		"unknown-array-object":   []byte(unknownArrayObject),
		"missing-carrier-auth":   []byte(missingCarrierAuth),
		"missing-local-key":      []byte(missingLocalPublicKey),
		"root-case-alias":        []byte(rootCaseAlias),
		"root-alias-duplicate":   []byte(rootAliasDuplicate),
		"nested-case-alias":      []byte(nestedCaseAlias),
		"nested-alias-duplicate": []byte(nestedAliasDuplicate),
		"array-case-alias":       []byte(arrayObjectCaseAlias),
		"array-alias-duplicate":  []byte(arrayObjectAliasDuplicate),
		"trailing":               append(append([]byte(nil), valid...), []byte(` {}`)...),
		"too-deep":               deeplyNested,
		"oversized":              bytes.Repeat([]byte("x"), MaxProductionProfileV2Size+1),
		"invalid-utf8":           append(append([]byte(nil), valid[:len(valid)-2]...), 0xff, '}', '\n'),
		"empty":                  nil,
		"whitespace":             []byte(" \n\t"),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeProductionProfileV2(bytes.NewReader(encoded)); !errors.Is(err, ErrInvalidProductionProfileV2) {
				t.Fatalf("ambiguous or unbounded JSON was accepted: %v", err)
			}
		})
	}
	if _, err := DecodeProductionProfileV2(nil); !errors.Is(err, ErrInvalidProductionProfileV2) {
		t.Fatalf("nil reader was accepted: %v", err)
	}
}

func TestDecodeProductionProfileV2RejectsLoneSurrogateEscapes(t *testing.T) {
	valid := productionProfileV2Fixture(t)
	replace := func(old, replacement string) []byte {
		t.Helper()
		mutated := strings.Replace(string(valid), old, replacement, 1)
		if mutated == string(valid) {
			t.Fatalf("fixture does not contain mutation target %q", old)
		}
		return []byte(mutated)
	}
	const displayName = `"display_name": "KyClash production pair fixture"`
	invalid := map[string][]byte{
		"display-lone-high": replace(
			displayName,
			`"display_name": "\uD800"`,
		),
		"display-lone-low": replace(
			displayName,
			`"display_name": "\uDC00"`,
		),
		"display-high-followed-by-text": replace(
			displayName,
			`"display_name": "\uD800x"`,
		),
		"display-two-high": replace(
			displayName,
			`"display_name": "\uD800\uD801"`,
		),
		"display-high-followed-by-escaped-backslash": replace(
			displayName,
			`"display_name": "\uD83D\\uDE00"`,
		),
	}
	for name, encoded := range invalid {
		t.Run(name, func(t *testing.T) {
			if validProductionProfileV2JSONStringScalars(encoded) {
				t.Fatal("raw JSON scalar preflight accepted a lone surrogate")
			}
			if _, err := DecodeProductionProfileV2(bytes.NewReader(encoded)); !errors.Is(err, ErrInvalidProductionProfileV2) {
				t.Fatalf("production decoder accepted a lone surrogate: %v", err)
			}
		})
	}

	accepted := map[string][]byte{
		"display-surrogate-pair": replace(
			displayName,
			`"display_name": "\uD83D\uDE00"`,
		),
		"display-actual-emoji": replace(
			displayName,
			`"display_name": "😀"`,
		),
		"display-escaped-backslash": replace(
			displayName,
			`"display_name": "\\uD800"`,
		),
		"profile-id-bmp-escape": replace(
			`"profile_id": "profile.test.production"`,
			`"profile_id": "\u0070rofile.test.production"`,
		),
	}
	for name, encoded := range accepted {
		t.Run(name, func(t *testing.T) {
			if !validProductionProfileV2JSONStringScalars(encoded) {
				t.Fatal("raw JSON scalar preflight rejected valid escaped content")
			}
			if _, err := DecodeProductionProfileV2(bytes.NewReader(encoded)); err != nil {
				t.Fatalf("production decoder rejected valid escaped content: %v", err)
			}
		})
	}
}

func TestProductionProfileV2JSONStringScalarPreflightCoversKeysAndNestedStrings(t *testing.T) {
	tests := map[string]struct {
		encoded string
		valid   bool
	}{
		"lone-high-value": {
			encoded: `{"value":"\uD800"}`,
		},
		"lone-low-key": {
			encoded: `{"\uDC00":"value"}`,
		},
		"nested-lone-low": {
			encoded: `{"nested":["\uDC00"]}`,
		},
		"endpoint-lone-high": {
			encoded: `{"url":"https://peer.example.invalid/\uD83D"}`,
		},
		"valid-surrogate-pair": {
			encoded: `{"value":"\uD83D\uDE00"}`,
			valid:   true,
		},
		"valid-lowercase-surrogate-pair": {
			encoded: `{"value":"\ud83d\ude00"}`,
			valid:   true,
		},
		"escaped-backslash-is-literal": {
			encoded: `{"value":"\\uD800"}`,
			valid:   true,
		},
		"escaped-quotes": {
			encoded: `{"value":"quoted \"text\""}`,
			valid:   true,
		},
		"actual-emoji": {
			encoded: `{"value":"😀"}`,
			valid:   true,
		},
		"ordinary-bmp-escape": {
			encoded: `{"value":"\u0070"}`,
			valid:   true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if validProductionProfileV2JSONStringScalars([]byte(test.encoded)) != test.valid {
				t.Fatalf("unexpected raw JSON scalar preflight result for %s", test.encoded)
			}
		})
	}
}

func TestProductionProfileV2PrivatePrefixCountIsBounded(t *testing.T) {
	candidate := validProductionProfileV2(t)
	candidate.Site.PrivateCIDRs = make([]string, 0, MaxProductionProfileV2PrivateCIDRs+1)
	for index := 0; index < MaxProductionProfileV2PrivateCIDRs; index++ {
		candidate.Site.PrivateCIDRs = append(candidate.Site.PrivateCIDRs, fmt.Sprintf("10.%d.0.0/16", index))
	}
	candidate.Site.PrivateCIDRs = append(candidate.Site.PrivateCIDRs, "fd00:127::/48")
	if err := candidate.Validate(); !errors.Is(err, ErrInvalidProductionProfileV2) {
		t.Fatalf("more than %d private CIDRs were accepted: %v", MaxProductionProfileV2PrivateCIDRs, err)
	}
}

func TestProductionProfileV2DisplayNameUsesTheSchemaCharacterBoundary(t *testing.T) {
	for _, accepted := range []string{
		"A",
		"KyClash production pair",
		strings.Repeat("界", 128),
		"\uFEFFaccepted",
		"accepted\uFEFF",
	} {
		candidate := validProductionProfileV2(t)
		candidate.Site.DisplayName = accepted
		if err := candidate.Validate(); err != nil {
			t.Fatalf("valid display name was rejected: %v", err)
		}
	}
	for _, rejected := range []string{
		"",
		" leading",
		"trailing ",
		"\u0085leading",
		"trailing\u0085",
		strings.Repeat("界", 129),
	} {
		candidate := validProductionProfileV2(t)
		candidate.Site.DisplayName = rejected
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidProductionProfileV2) {
			t.Fatalf("invalid display name was accepted: %v", err)
		}
	}
}

func TestProductionProfileV2FormattingRedactsPairMaterial(t *testing.T) {
	candidate := validProductionProfileV2(t)
	formatted := candidate.String()
	for _, forbidden := range []string{
		candidate.Tunnel.LocalPublicKey,
		candidate.Tunnel.PeerPublicKey,
		candidate.Tunnel.LocalAddresses[0],
		candidate.Site.PrivateCIDRs[0],
		candidate.Transports.Endpoints[0].URL,
	} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("production profile formatting leaked %q", forbidden)
		}
	}
}
