package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunAuthenticatesWithoutEchoingSecrets(t *testing.T) {
	secret := bytes.Repeat([]byte{9}, 32)
	encodedSecret := base64.StdEncoding.EncodeToString(secret)
	input := `{"protocol_version":1,"instance_id":"instance-123","auth_token":"` + encodedSecret + `","private_key":"` + encodedSecret + `"}` + "\n"
	var output bytes.Buffer
	if err := run(nil, strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), encodedSecret) {
		t.Fatal("handshake leaked secret")
	}
	var response handshake
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ProtocolVersion != 1 || response.InstanceID != "instance-123" || len(response.AuthProof) != 64 {
		t.Fatalf("unexpected handshake: %#v", response)
	}
}

func TestRunRejectsArgumentsWithoutReadingSecrets(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"--private-key=secret"}, strings.NewReader(""), &output); err == nil {
		t.Fatal("expected argument refusal")
	}
	if output.Len() != 0 {
		t.Fatal("argument refusal wrote output")
	}
}
