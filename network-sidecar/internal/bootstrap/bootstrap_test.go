package bootstrap

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

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
