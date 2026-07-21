package bootstrap

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestSharedBootstrapFixture(t *testing.T) {
	fixture, err := os.ReadFile("../../../schemas/fixtures/network-sidecar-bootstrap-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	config, err := DecodeLine(bufio.NewReader(strings.NewReader(string(fixture))))
	if err != nil {
		t.Fatal(err)
	}
	defer config.Clear()
	if config.ProtocolVersion != ProtocolVersion || config.InstanceID != "fixture_instance" || len(config.AuthToken) != 32 || len(config.PrivateKey) != 32 {
		t.Fatalf("unexpected shared fixture: %s", config)
	}
}

func validMessage() string {
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	return `{"protocol_version":1,"instance_id":"instance-123","auth_token":"` + secret + `","private_key":"` + secret + `"}` + "\n"
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
		strings.Replace(valid, `"protocol_version":1`, `"protocol_version":2`, 1),
		strings.Replace(valid, `"instance_id":"instance-123"`, `"instance_id":"../bad"`, 1),
		strings.Replace(valid, "}", `,"unknown":true}`, 1),
		valid + valid,
	} {
		if _, err := DecodeLine(bufio.NewReader(strings.NewReader(message + "\n"))); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("expected invalid config for %q, got %v", message, err)
		}
	}
}

func TestBootstrapMessageBound(t *testing.T) {
	message := strings.Repeat("x", maxMessageSize+1) + "\n"
	if _, err := DecodeLine(bufio.NewReaderSize(strings.NewReader(message), maxMessageSize+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("expected message bound, got %v", err)
	}
}
