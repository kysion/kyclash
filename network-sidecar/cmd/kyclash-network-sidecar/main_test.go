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
	input := `{"protocol_version":1,"instance_id":"instance-123","auth_token":"` + encodedSecret + `","private_key":"` + encodedSecret + `"}` + "\n" +
		`{"protocol_version":1,"request_id":"request.stop","payload":{"type":"disconnect"}}` + "\n"
	var output bytes.Buffer
	if err := run(nil, strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), encodedSecret) {
		t.Fatal("handshake leaked secret")
	}
	var response handshake
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("expected handshake and stop response, got %q", output.String())
	}
	if err := json.Unmarshal(lines[0], &response); err != nil {
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

func TestEntrypointNeverLeaksArgumentsEnvironmentOrMalformedInput(t *testing.T) {
	argumentSecret := "argument-secret-must-not-leak"
	environmentSecret := "environment-secret-must-not-leak"
	inputSecret := "input-secret-must-not-leak"
	t.Setenv("KYCLASH_TEST_SECRET", environmentSecret)

	for name, testCase := range map[string]struct {
		arguments []string
		input     string
	}{
		"argument": {arguments: []string{"--private-key=" + argumentSecret}},
		"malformed bootstrap": {
			input: `{"protocol_version":1,"instance_id":"instance-123","auth_token":"` + inputSecret + `"}` + "\n",
		},
		"malformed IPC": {
			input: func() string {
				secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
				return `{"protocol_version":1,"instance_id":"instance-123","auth_token":"` + secret + `","private_key":"` + secret + `"}` + "\n" +
					`{"protocol_version":1,"request_id":"request.test","payload":{"type":"` + inputSecret + `"},"unknown":true}` + "\n"
			}(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if exitCode := execute(testCase.arguments, strings.NewReader(testCase.input), &stdout, &stderr); exitCode != 1 {
				t.Fatalf("expected failure exit code, got %d", exitCode)
			}
			combined := stdout.String() + stderr.String()
			for _, secret := range []string{argumentSecret, environmentSecret, inputSecret} {
				if strings.Contains(combined, secret) {
					t.Fatalf("process output leaked secret %q", secret)
				}
			}
			if stderr.String() != "KyClash network sidecar bootstrap failed\n" {
				t.Fatalf("unexpected diagnostic output: %q", stderr.String())
			}
		})
	}
}
