package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func validFixture(t *testing.T) []byte {
	t.Helper()
	fixture, err := os.ReadFile("../../../schemas/fixtures/network-v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestSharedProfileDecodesAndNormalizesEndpoints(t *testing.T) {
	decoded, err := Decode(validFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if TunnelMTU != 1_420 {
		t.Fatal("unexpected locked tunnel MTU")
	}
	for transport, expected := range map[Transport]string{
		QUIC: "edge.example.test:443",
		WSS:  "edge.example.test:443",
		TCP:  "edge.example.test:443",
	} {
		endpoint, endpointErr := decoded.Endpoint(transport)
		if endpointErr != nil || endpoint.Address != expected || endpoint.ServerName != "edge.example.test" {
			t.Fatalf("unexpected %s endpoint: %#v %v", transport, endpoint, endpointErr)
		}
	}
	key, err := decoded.PeerKeyBytes()
	if err != nil || len(key) != 32 {
		t.Fatal("WireGuard public key did not decode to 32 bytes")
	}
	clear(key)
}

func TestProfileFailsClosedOnContractViolations(t *testing.T) {
	var original map[string]interface{}
	if err := json.Unmarshal(validFixture(t), &original); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string]interface{}){
		"version": func(value map[string]interface{}) { value["schema_version"] = 2 },
		"key": func(value map[string]interface{}) {
			value["tunnel"].(map[string]interface{})["peer_public_key"] = "invalid"
		},
		"identity": func(value map[string]interface{}) { value["identity_ref"] = "file:forbidden" },
		"endpoint query": func(value map[string]interface{}) {
			value["transports"].(map[string]interface{})["endpoints"].([]interface{})[0].(map[string]interface{})["url"] = "https://edge.example.test:443?token=forbidden"
		},
		"duplicate endpoint": func(value map[string]interface{}) {
			endpoints := value["transports"].(map[string]interface{})["endpoints"].([]interface{})
			value["transports"].(map[string]interface{})["endpoints"] = append(endpoints, endpoints[0])
		},
		"missing endpoint": func(value map[string]interface{}) {
			value["transports"].(map[string]interface{})["endpoints"] = value["transports"].(map[string]interface{})["endpoints"].([]interface{})[:2]
		},
		"unknown field": func(value map[string]interface{}) { value["unknown"] = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			copyBytes, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var value map[string]interface{}
			if err := json.Unmarshal(copyBytes, &value); err != nil {
				t.Fatal(err)
			}
			mutate(value)
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(encoded); err == nil {
				t.Fatal("expected strict profile refusal")
			}
		})
	}
}

func TestProfileFormattingRedactsKeyAndEndpoints(t *testing.T) {
	decoded, err := Decode(validFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%v", *decoded)
	if strings.Contains(formatted, decoded.Tunnel.PeerPublicKey) || bytes.Contains([]byte(formatted), []byte("edge.example.test")) {
		t.Fatalf("profile formatting leaked protected fields: %s", formatted)
	}
}
