package productionpeer

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

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

func validConfig(t *testing.T) Config {
	t.Helper()
	encoded, err := os.ReadFile("testdata/valid-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeConfig(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	return *decoded
}

func TestValidConfigRoundTripsStrictly(t *testing.T) {
	config := validConfig(t)
	if config.SchemaVersion != ConfigSchemaVersion ||
		config.CarrierAuthVersion != CarrierAuthVersionV1 ||
		len(config.WireGuard.Clients) != MaxAuthorizedClients ||
		config.Forwarding.Mode != ForwardingBrokeredLinuxTUNFD ||
		config.Forwarding.TunnelInterface != TunnelInterface ||
		config.Policy.ShutdownGraceSeconds != RequiredShutdownGraceSecs ||
		config.Listeners[0].Transport != profile.QUIC ||
		config.Listeners[1].Transport != profile.WSS ||
		config.Listeners[2].Transport != profile.TCP {
		t.Fatal("valid fixture did not retain its locked contract")
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeConfig(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PeerID != config.PeerID || decoded.DeploymentID != config.DeploymentID {
		t.Fatal("identity fields changed during strict round trip")
	}
}

func TestConfigRejectsLowOrderAndNoncanonicalX25519PublicKeys(t *testing.T) {
	lowOrderOne := make([]byte, 32)
	lowOrderOne[0] = 1
	lowOrderToolchain, err := hex.DecodeString(
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
	)
	if err != nil {
		t.Fatal(err)
	}
	highBitAlias := bytes.Repeat([]byte{0x22}, 32)
	highBitAlias[31] |= 0x80
	fieldAlias := bytes.Repeat([]byte{0xff}, 32)
	fieldAlias[0] = 0xf6
	fieldAlias[31] = 0x7f
	invalidKeys := map[string]string{
		"low-order-u1":          base64.StdEncoding.EncodeToString(lowOrderOne),
		"low-order-toolchain":   base64.StdEncoding.EncodeToString(lowOrderToolchain),
		"x25519-high-bit-alias": base64.StdEncoding.EncodeToString(highBitAlias),
		"x25519-field-alias":    base64.StdEncoding.EncodeToString(fieldAlias),
	}
	clear(lowOrderOne)
	clear(lowOrderToolchain)
	clear(highBitAlias)
	clear(fieldAlias)
	for name, invalid := range invalidKeys {
		for field, mutate := range map[string]func(*Config){
			"server": func(candidate *Config) {
				candidate.WireGuard.ServerPublicKeyBase64 = invalid
			},
			"client": func(candidate *Config) {
				candidate.WireGuard.Clients[0].PublicKeyBase64 = invalid
			},
		} {
			t.Run(name+"/"+field, func(t *testing.T) {
				candidate := validConfig(t)
				mutate(&candidate)
				if err := candidate.Validate(); !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("invalid X25519 public key was accepted: %v", err)
				}
			})
		}
	}
}

func TestDecodeConfigRejectsSupersededV1AndCarrierAuthVersionDrift(t *testing.T) {
	v1, err := os.ReadFile("testdata/valid-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeConfig(bytes.NewReader(v1)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("superseded schema-v1 configuration was accepted: %v", err)
	}

	v2, err := os.ReadFile("testdata/valid-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string]string{
		"missing": strings.Replace(
			string(v2),
			"  \"carrier_auth_version\": 1,\n",
			"",
			1,
		),
		"unknown": strings.Replace(
			string(v2),
			`"carrier_auth_version": 1`,
			`"carrier_auth_version": 2`,
			1,
		),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeConfig(strings.NewReader(encoded)); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("carrier auth version drift was accepted: %v", err)
			}
		})
	}
}

func TestConfigStringRedactsTrustEndpointsAndRoutes(t *testing.T) {
	config := validConfig(t)
	formatted := config.String()
	for _, forbidden := range []string{
		config.TLS.ServerName,
		config.TLS.LocalCertificateSHA256,
		config.WireGuard.ServerPublicKeyBase64,
		config.WireGuard.Clients[0].PublicKeyBase64,
		config.Listeners[0].Bind,
		config.Listeners[0].URL,
		config.Forwarding.PrivateCIDRs[0],
	} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("formatted config leaked %q", forbidden)
		}
	}
}

func TestDecodeConfigRejectsDuplicateKeysAtEveryDepth(t *testing.T) {
	valid, err := os.ReadFile("testdata/valid-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	rootDuplicate := strings.Replace(
		string(valid),
		`"schema_version": 2,`,
		`"schema_version": 2, "schema_version": 2,`,
		1,
	)
	nestedDuplicate := strings.Replace(
		string(valid),
		`"server_name": "peer.example.invalid",`,
		`"server_name": "peer.example.invalid", "server_name": "peer.example.invalid",`,
		1,
	)
	arrayObjectDuplicate := strings.Replace(
		string(valid),
		`"transport": "quic",`,
		`"transport": "quic", "transport": "quic",`,
		1,
	)
	for name, encoded := range map[string]string{
		"root":         rootDuplicate,
		"nested":       nestedDuplicate,
		"array-object": arrayObjectDuplicate,
	} {
		t.Run(name, func(t *testing.T) {
			if uniqueJSONKeys([]byte(encoded)) {
				t.Fatal("duplicate-key preflight accepted ambiguous JSON")
			}
			if _, err := DecodeConfig(strings.NewReader(encoded)); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected duplicate-key refusal, got %v", err)
			}
		})
	}
	if !uniqueJSONKeys(valid) {
		t.Fatal("valid fixture failed duplicate-key preflight")
	}
	deeplyNested := strings.Repeat("[", MaxConfigJSONDepth+1) +
		"0" +
		strings.Repeat("]", MaxConfigJSONDepth+1)
	if uniqueJSONKeys([]byte(deeplyNested)) {
		t.Fatal("unbounded JSON nesting was accepted")
	}
}

func TestDecodeConfigRejectsCaseAliasesAndAliasOverwritesAtEveryObjectLevel(t *testing.T) {
	valid, err := os.ReadFile("testdata/valid-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	replace := func(old, replacement string) []byte {
		t.Helper()
		mutated := strings.Replace(string(valid), old, replacement, 1)
		if mutated == string(valid) {
			t.Fatalf("fixture does not contain mutation target %q", old)
		}
		return []byte(mutated)
	}
	tests := map[string][]byte{
		"root-case-alias": replace(
			`"schema_version": 2`,
			`"SCHEMA_VERSION": 2`,
		),
		"root-alias-overwrite": replace(
			`"schema_version": 2`,
			`"schema_version": 1, "SCHEMA_VERSION": 2`,
		),
		"tls-case-alias": replace(
			`"server_name": "peer.example.invalid"`,
			`"SERVER_NAME": "peer.example.invalid"`,
		),
		"tls-alias-overwrite": replace(
			`"server_name": "peer.example.invalid"`,
			`"server_name": "wrong.example.invalid", "Server_Name": "peer.example.invalid"`,
		),
		"wireguard-case-alias": replace(
			`"mtu": 1420`,
			`"MTU": 1420`,
		),
		"wireguard-alias-overwrite": replace(
			`"mtu": 1420`,
			`"mtu": 1419, "MTU": 1420`,
		),
		"client-case-alias": replace(
			`"id": "client.test.macos"`,
			`"ID": "client.test.macos"`,
		),
		"client-alias-overwrite": replace(
			`"id": "client.test.macos"`,
			`"id": "invalid/id", "ID": "client.test.macos"`,
		),
		"listener-case-alias": replace(
			`"url": "https://peer.example.invalid:2443"`,
			`"URL": "https://peer.example.invalid:2443"`,
		),
		"listener-alias-overwrite": replace(
			`"url": "https://peer.example.invalid:2443"`,
			`"url": "https://wrong.example.invalid:2443", "URL": "https://peer.example.invalid:2443"`,
		),
		"forwarding-case-alias": replace(
			`"mode": "brokered_linux_tun_fd"`,
			`"MODE": "brokered_linux_tun_fd"`,
		),
		"forwarding-alias-overwrite": replace(
			`"mode": "brokered_linux_tun_fd"`,
			`"mode": "preprovisioned_linux_tun", "Mode": "brokered_linux_tun_fd"`,
		),
		"return-path-case-alias": replace(
			`"mode": "routed"`,
			`"MODE": "routed"`,
		),
		"return-path-alias-overwrite": replace(
			`"mode": "routed"`,
			`"mode": "nat", "Mode": "routed"`,
		),
		"policy-case-alias": replace(
			`"shutdown_grace_seconds": 10`,
			`"SHUTDOWN_GRACE_SECONDS": 10`,
		),
		"policy-alias-overwrite": replace(
			`"shutdown_grace_seconds": 10`,
			`"shutdown_grace_seconds": 9, "Shutdown_Grace_Seconds": 10`,
		),
	}
	if !uniqueJSONKeys(valid) || !exactConfigJSONKeys(valid) {
		t.Fatal("valid fixture failed strict JSON preflight")
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if !uniqueJSONKeys(encoded) {
				t.Fatal("case alias fixture unexpectedly contains an exact duplicate key")
			}
			if exactConfigJSONKeys(encoded) {
				t.Fatal("exact-key preflight accepted a case alias")
			}
			if _, err := DecodeConfig(bytes.NewReader(encoded)); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("case alias or alias overwrite was accepted: %v", err)
			}
		})
	}
}

func TestDecodeConfigRejectsUnknownTrailingAndOversizedInput(t *testing.T) {
	valid, err := os.ReadFile("testdata/valid-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(valid, &object); err != nil {
		t.Fatal(err)
	}
	object["private_key"] = strings.Repeat("secret", 8)
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{
		"unknown":   unknown,
		"trailing":  append(append([]byte(nil), valid...), []byte(` {}`)...),
		"oversized": bytes.Repeat([]byte("x"), MaxConfigSize+1),
		"invalid-utf8": append(
			append([]byte(nil), valid[:len(valid)-2]...),
			0xff,
			'}',
			'\n',
		),
		"empty": nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeConfig(bytes.NewReader(encoded)); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected invalid config, got %v", err)
			}
		})
	}
}

func TestTLSAndListenerContractFailsClosed(t *testing.T) {
	tests := map[string]func(*Config){
		"private-ca-mode": func(config *Config) {
			config.TLS.ClientTrustMode = "private_ca"
		},
		"tls12": func(config *Config) {
			config.TLS.MinimumVersion = "1.2"
		},
		"uppercase-server-name": func(config *Config) {
			config.TLS.ServerName = "Peer.Example.Invalid"
		},
		"ipv4-server-name": func(config *Config) {
			config.TLS.ServerName = "192.0.2.10"
		},
		"ipv6-server-name": func(config *Config) {
			config.TLS.ServerName = "2001:db8::10"
		},
		"single-label-server-name": func(config *Config) {
			config.TLS.ServerName = "peer"
		},
		"trailing-dot-server-name": func(config *Config) {
			config.TLS.ServerName = "peer.example.invalid."
		},
		"zero-certificate-hash": func(config *Config) {
			config.TLS.LocalCertificateSHA256 = strings.Repeat("0", 64)
		},
		"mutual-tls-downgrade": func(config *Config) {
			config.TLS.ClientAuthentication = "none"
		},
		"wrong-order": func(config *Config) {
			config.Listeners[0], config.Listeners[1] = config.Listeners[1], config.Listeners[0]
		},
		"loopback-bind": func(config *Config) {
			config.Listeners[0].Bind = "127.0.0.1:2443"
		},
		"wildcard-bind": func(config *Config) {
			config.Listeners[0].Bind = "0.0.0.0:2443"
		},
		"privileged-bind-port": func(config *Config) {
			config.Listeners[0].Bind = "192.0.2.10:443"
		},
		"different-bind-address": func(config *Config) {
			config.Listeners[1].Bind = "192.0.2.11:2444"
		},
		"duplicate-bind-port": func(config *Config) {
			config.Listeners[2].Bind = "192.0.2.10:2444"
			config.Listeners[2].URL = "tcp://peer.example.invalid:2444"
		},
		"global-ipv6-bind": func(config *Config) {
			config.Listeners[0].Bind = "[2001:db8::10]:2443"
		},
		"link-local-ipv6-bind": func(config *Config) {
			config.Listeners[0].Bind = "[fe80::10]:2443"
		},
		"mapped-ipv6-bind": func(config *Config) {
			config.Listeners[0].Bind = "[::ffff:192.0.2.10]:2443"
		},
		"noncanonical-bind-port": func(config *Config) {
			config.Listeners[0].Bind = "192.0.2.10:02443"
		},
		"url-with-credential": func(config *Config) {
			config.Listeners[0].URL = "https://user@peer.example.invalid:2443"
		},
		"url-with-query": func(config *Config) {
			config.Listeners[1].URL = "wss://peer.example.invalid:2444/kynp?token=no"
		},
		"wrong-wss-path": func(config *Config) {
			config.Listeners[1].URL = "wss://peer.example.invalid:2444/other"
		},
		"wrong-hostname": func(config *Config) {
			config.Listeners[2].URL = "tcp://other.example.invalid:2445"
		},
		"url-bind-port-mismatch": func(config *Config) {
			config.Listeners[0].URL = "https://peer.example.invalid:3443"
		},
		"implicit-port": func(config *Config) {
			config.Listeners[0].URL = "https://peer.example.invalid"
		},
		"noncanonical-url-port": func(config *Config) {
			config.Listeners[0].URL = "https://peer.example.invalid:02443"
		},
		"url-empty-query-marker": func(config *Config) {
			config.Listeners[0].URL = "https://peer.example.invalid:2443?"
		},
		"url-raw-path": func(config *Config) {
			config.Listeners[1].URL = "wss://peer.example.invalid:2444/%6bynp"
		},
		"url-fragment": func(config *Config) {
			config.Listeners[0].URL = "https://peer.example.invalid:2443#fragment"
		},
		"opaque-url": func(config *Config) {
			config.Listeners[0].URL = "https:peer.example.invalid:2443"
		},
		"duplicate-bind": func(config *Config) {
			config.Listeners[2].Bind = config.Listeners[1].Bind
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validConfig(t)
			mutate(&config)
			if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected invalid config, got %v", err)
			}
		})
	}
}

func TestServerNameContractRejectsNumericAndMalformedDNSNames(t *testing.T) {
	for _, value := range []string{
		"127.1",
		"123.456",
		"999.999.999.999",
		"a..b",
		"-a.example",
		"a-.example",
	} {
		if validServerName(value) {
			t.Fatalf("noncanonical or IP-like DNS name was accepted: %q", value)
		}
	}
	for _, value := range []string{
		"peer.example.invalid",
		"1-2.example",
		"1.example",
	} {
		if !validServerName(value) {
			t.Fatalf("canonical DNS name was rejected: %q", value)
		}
	}
}

func TestWireGuardIdentityAndAddressContractFailsClosed(t *testing.T) {
	tests := map[string]func(*Config){
		"raw-private-key-field-is-not-in-schema": func(config *Config) {
			config.WireGuard.ServerPublicKeyBase64 = "not-base64"
		},
		"zero-public-key": func(config *Config) {
			config.WireGuard.ServerPublicKeyBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		},
		"same-public-key": func(config *Config) {
			config.WireGuard.Clients[0].PublicKeyBase64 = config.WireGuard.ServerPublicKeyBase64
		},
		"public-key-newline": func(config *Config) {
			config.WireGuard.ServerPublicKeyBase64 += "\n"
		},
		"public-key-carriage-return": func(config *Config) {
			config.WireGuard.Clients[0].PublicKeyBase64 += "\r"
		},
		"public-key-nonzero-padding-bits": func(config *Config) {
			value := config.WireGuard.ServerPublicKeyBase64
			config.WireGuard.ServerPublicKeyBase64 = value[:len(value)-2] + "F="
		},
		"network-tunnel-prefix": func(config *Config) {
			config.WireGuard.ServerAddresses[0] = "10.255.255.0/24"
		},
		"mapped-tunnel-address": func(config *Config) {
			config.WireGuard.Clients[0].TunnelAddresses[0] = "::ffff:10.255.255.2/128"
		},
		"zoned-tunnel-address": func(config *Config) {
			config.WireGuard.Clients[0].TunnelAddresses[1] = "fd00:255::2%en0/128"
		},
		"noncanonical-tunnel-address": func(config *Config) {
			config.WireGuard.ServerAddresses[1] = "FD00:255::1/128"
		},
		"public-tunnel-address": func(config *Config) {
			config.WireGuard.Clients[0].TunnelAddresses[0] = "192.0.2.20/32"
		},
		"duplicate-address-family": func(config *Config) {
			config.WireGuard.ServerAddresses[1] = "10.255.255.3/32"
		},
		"family-mismatch": func(config *Config) {
			config.WireGuard.Clients[0].TunnelAddresses = config.WireGuard.Clients[0].TunnelAddresses[:1]
		},
		"overlap": func(config *Config) {
			config.WireGuard.Clients[0].TunnelAddresses[0] = config.WireGuard.ServerAddresses[0]
		},
		"changed-mtu": func(config *Config) {
			config.WireGuard.MTU = 1280
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validConfig(t)
			mutate(&config)
			if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected invalid config, got %v", err)
			}
		})
	}
}

func TestWireGuardContractRequiresExactlyOneConfiguredAndActiveClient(t *testing.T) {
	if MaxAuthorizedClients != 1 {
		t.Fatalf("configured-client authority drifted to %d", MaxAuthorizedClients)
	}

	none := validConfig(t)
	none.WireGuard.Clients = nil
	if err := none.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("zero configured clients were accepted: %v", err)
	}

	two := validConfig(t)
	two.WireGuard.Clients = append(two.WireGuard.Clients, ClientConfig{
		ID:              "client.test.second",
		PublicKeyBase64: "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=",
		TunnelAddresses: []string{"10.255.255.3/32", "fd00:255::3/128"},
	})
	if err := two.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("more than one configured client was accepted: %v", err)
	}

	active := validConfig(t)
	active.Policy.MaxActiveClients = 2
	if err := active.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("more than one active client was accepted: %v", err)
	}
}

func TestForwardingContractAcceptsLockedShenzhenRoutes(t *testing.T) {
	config := validConfig(t)
	config.WireGuard.ServerAddresses = config.WireGuard.ServerAddresses[:1]
	config.WireGuard.Clients[0].TunnelAddresses =
		config.WireGuard.Clients[0].TunnelAddresses[:1]
	config.Forwarding.PrivateCIDRs = []string{
		"10.68.72.0/21",
		"10.20.81.0/24",
		"10.68.64.30/32",
		"10.68.64.31/32",
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestForwardingAddressFamiliesMustMatchEndToEnd(t *testing.T) {
	dualTunnelIPv4Routes := validConfig(t)
	dualTunnelIPv4Routes.Forwarding.PrivateCIDRs = []string{"10.127.0.0/16"}
	if err := dualTunnelIPv4Routes.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("dual-stack tunnel with IPv4-only routes was accepted: %v", err)
	}

	ipv4TunnelDualRoutes := validConfig(t)
	ipv4TunnelDualRoutes.WireGuard.ServerAddresses =
		ipv4TunnelDualRoutes.WireGuard.ServerAddresses[:1]
	ipv4TunnelDualRoutes.WireGuard.Clients[0].TunnelAddresses =
		ipv4TunnelDualRoutes.WireGuard.Clients[0].TunnelAddresses[:1]
	if err := ipv4TunnelDualRoutes.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("IPv4-only tunnel with dual-stack routes was accepted: %v", err)
	}
}

func TestForwardingContractRejectsBroadUnsafeAndOverlappingRoutes(t *testing.T) {
	tests := map[string][]string{
		"default":             {"0.0.0.0/0"},
		"public":              {"192.0.2.0/24"},
		"host-bits":           {"10.68.72.1/21"},
		"mapped-ipv6":         {"::ffff:10.68.72.0/120"},
		"zoned-ipv6":          {"fd00:127::%en0/48"},
		"noncanonical-ipv6":   {"FD00:127::/48"},
		"noncanonical-ipv4":   {"10.068.72.0/21"},
		"overlap":             {"10.68.72.0/21", "10.68.76.0/24"},
		"tunnel-overlap":      {"10.255.255.1/32"},
		"crosses-10-private":  {"10.0.0.0/7"},
		"crosses-192-private": {"192.168.0.0/15"},
		"crosses-ula":         {"fc00::/6"},
	}
	for name, routes := range tests {
		t.Run(name, func(t *testing.T) {
			config := validConfig(t)
			config.Forwarding.PrivateCIDRs = routes
			if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected invalid config, got %v", err)
			}
		})
	}
}

func TestForwardingPrivateCIDRCountAndTextBounds(t *testing.T) {
	if MaxPrivateCIDRs != 16 || MaxPrivateCIDRTextBytes != 1024 {
		t.Fatalf(
			"private-prefix bounds drifted: count=%d text=%d",
			MaxPrivateCIDRs,
			MaxPrivateCIDRTextBytes,
		)
	}

	config := validConfig(t)
	config.WireGuard.ServerAddresses = config.WireGuard.ServerAddresses[:1]
	config.WireGuard.Clients[0].TunnelAddresses =
		config.WireGuard.Clients[0].TunnelAddresses[:1]
	config.Forwarding.PrivateCIDRs = make([]string, 0, MaxPrivateCIDRs)
	textBytes := 0
	for index := 1; index <= MaxPrivateCIDRs; index++ {
		prefix := fmt.Sprintf("10.127.0.%d/32", index)
		config.Forwarding.PrivateCIDRs = append(config.Forwarding.PrivateCIDRs, prefix)
		textBytes += len(prefix)
	}
	if textBytes > MaxPrivateCIDRTextBytes {
		t.Fatalf("canonical maximum-count fixture unexpectedly exceeds text cap: %d", textBytes)
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("maximum canonical private-prefix set was rejected: %v", err)
	}

	config.Forwarding.PrivateCIDRs = append(
		config.Forwarding.PrivateCIDRs,
		"10.127.0.17/32",
	)
	if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("more than %d private prefixes were accepted: %v", MaxPrivateCIDRs, err)
	}

	oversizedText := validConfig(t)
	oversizedText.Forwarding.PrivateCIDRs = make([]string, MaxPrivateCIDRs)
	for index := range oversizedText.Forwarding.PrivateCIDRs {
		oversizedText.Forwarding.PrivateCIDRs[index] = strings.Repeat(
			"a",
			MaxPrivateCIDRTextBytes/MaxPrivateCIDRs+1,
		)
	}
	if err := oversizedText.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("private-prefix text beyond %d bytes was accepted: %v", MaxPrivateCIDRTextBytes, err)
	}
}

func TestForwardingAndLifecycleAuthorityCannotBeExpanded(t *testing.T) {
	tests := map[string]func(*Config){
		"runtime-created-tun": func(config *Config) {
			config.Forwarding.Mode = "create_linux_tun"
		},
		"superseded-preprovisioned-tun": func(config *Config) {
			config.Forwarding.Mode = "preprovisioned_linux_tun"
		},
		"caller-selected-tun": func(config *Config) {
			config.Forwarding.TunnelInterface = "wg0"
		},
		"loopback-site": func(config *Config) {
			config.Forwarding.SiteInterface = "lo"
		},
		"nat": func(config *Config) {
			config.Forwarding.ReturnPath.Mode = "masquerade"
		},
		"multiple-carriers": func(config *Config) {
			config.Policy.MaxActiveCarriers = 2
		},
		"multiple-active-clients": func(config *Config) {
			config.Policy.MaxActiveClients = 2
		},
		"unbounded-idle": func(config *Config) {
			config.Policy.IdleTimeoutSeconds = 0
		},
		"short-shutdown": func(config *Config) {
			config.Policy.ShutdownGraceSeconds = RequiredShutdownGraceSecs - 1
		},
		"long-shutdown": func(config *Config) {
			config.Policy.ShutdownGraceSeconds = RequiredShutdownGraceSecs + 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validConfig(t)
			mutate(&config)
			if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected invalid config, got %v", err)
			}
		})
	}
}
