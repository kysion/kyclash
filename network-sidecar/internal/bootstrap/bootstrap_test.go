package bootstrap

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestSharedBootstrapFixture(t *testing.T) {
	fixture, err := os.ReadFile("../../../schemas/fixtures/network-sidecar-bootstrap-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, fixture); err != nil {
		t.Fatal(err)
	}
	compact.WriteByte('\n')
	config, err := DecodeLine(bufio.NewReader(bytes.NewReader(compact.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	defer config.Clear()
	if config.ProtocolVersion != ProtocolVersion || config.InstanceID != "kyclash.0123456789abcdef0123456789abcdef" || len(config.AuthToken) != 32 || len(config.PrivateKey) != 32 {
		t.Fatalf("unexpected shared fixture: %s", config)
	}
	handshakeFixture, err := os.ReadFile("../../../schemas/fixtures/network-sidecar-handshake-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		ProtocolVersion uint8  `json:"protocol_version"`
		InstanceID      string `json:"instance_id"`
		AuthProof       string `json:"auth_proof"`
	}
	decoder := json.NewDecoder(bytes.NewReader(handshakeFixture))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&expected); err != nil {
		t.Fatal(err)
	}
	if expected.ProtocolVersion != ProtocolVersion || expected.InstanceID != config.InstanceID || expected.AuthProof != AuthProof(config) {
		t.Fatalf("v2 handshake/HMAC diverged from shared contract: %#v", expected)
	}
}

func TestHistoricalV1BootstrapFixtureIsRejected(t *testing.T) {
	fixture, err := os.ReadFile("../../../schemas/fixtures/network-sidecar-bootstrap-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLine(bufio.NewReader(bytes.NewReader(append(fixture, '\n')))); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected historical v1 bootstrap rejection, got %v", err)
	}
}

func validMessage() string {
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	return `{"protocol_version":2,"instance_id":"instance-123","auth_token":"` + secret + `","private_key":"` + secret + `"}` + "\n"
}

func TestBootstrapDecodesProvesAndClearsSecrets(t *testing.T) {
	config, err := DecodeLine(bufio.NewReader(strings.NewReader(validMessage())))
	if err != nil {
		t.Fatal(err)
	}
	proof := AuthProof(config)
	if len(proof) != 64 || strings.Contains(config.String(), base64.StdEncoding.EncodeToString(config.AuthToken)) {
		t.Fatal("bootstrap proof or redaction failed")
	}
	config.Clear()
	for _, secret := range append(config.AuthToken, config.PrivateKey...) {
		if secret != 0 {
			t.Fatal("secret was not cleared")
		}
	}
}

func TestBootstrapFailsClosed(t *testing.T) {
	valid := strings.TrimSuffix(validMessage(), "\n")
	for _, message := range []string{
		`{}`,
		strings.Replace(valid, `"protocol_version":2`, `"protocol_version":1`, 1),
		strings.Replace(valid, `"protocol_version":2`, `"protocol_version":3`, 1),
		strings.Replace(valid, `"instance_id":"instance-123"`, `"instance_id":"../bad"`, 1),
		strings.Replace(valid, `"instance_id":"instance-123"`, `"instance_id":".instance-123"`, 1),
		strings.Replace(valid, `"instance_id":"instance-123"`, `"instance_id":"instance-123."`, 1),
		strings.Replace(valid, `"instance_id":"instance-123"`, `"instance_id":"instance..123"`, 1),
		strings.Replace(valid, `"instance_id":"instance-123"`, `"instance_id":"instance/path"`, 1),
		strings.Replace(valid, `"instance_id":"instance-123"`, `"instance_id":"instance\\\\path"`, 1),
		strings.Replace(valid, "}", `,"unknown":true}`, 1),
		valid + valid,
	} {
		if _, err := DecodeLine(bufio.NewReader(strings.NewReader(message + "\n"))); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("expected invalid config for %q, got %v", message, err)
		}
	}
}

func TestBootstrapRejectsCompleteJSONWithoutLF(t *testing.T) {
	message := strings.TrimSuffix(validMessage(), "\n")
	if _, err := DecodeLine(bufio.NewReader(strings.NewReader(message))); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected unterminated bootstrap refusal, got %v", err)
	}
}

func TestBootstrapMessageBound(t *testing.T) {
	message := strings.Repeat("x", maxMessageSize+1) + "\n"
	if _, err := DecodeLine(bufio.NewReaderSize(strings.NewReader(message), maxMessageSize+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("expected message bound, got %v", err)
	}
}
