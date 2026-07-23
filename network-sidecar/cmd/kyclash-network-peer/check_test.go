package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/productionpeer"
)

func TestCheckConfigAcceptsOnlyTheStrictPublicContract(t *testing.T) {
	encoded, err := os.ReadFile("../../internal/productionpeer/testdata/valid-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := runCheck([]string{"--check-config"}, bytes.NewReader(encoded), &stdout); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "KYCLASH_LINUX_PEER_CONFIG_OK\n" {
		t.Fatalf("unexpected public output: %q", stdout.String())
	}
}

func TestCheckConfigRejectsSupersededV1(t *testing.T) {
	encoded, err := os.ReadFile("../../internal/productionpeer/testdata/valid-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err = runCheck([]string{"--check-config"}, bytes.NewReader(encoded), &stdout)
	if !errors.Is(err, productionpeer.ErrInvalidConfig) {
		t.Fatalf("expected schema-v1 refusal, got %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("superseded config wrote public success output: %q", stdout.String())
	}
}

func TestCheckConfigHasNoLiveOrCallerSelectedMode(t *testing.T) {
	for name, arguments := range map[string][]string{
		"none":                 nil,
		"live":                 {"--run"},
		"path":                 {"--check-config", "/tmp/other.json"},
		"listen":               {"--listen", "0.0.0.0:443"},
		"credential":           {"--private-key", "secret"},
		"credential-directory": {"--credential-directory", "/tmp/credentials"},
		"credential-name":      {"--wireguard-private-credential", "other"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			if err := runCheck(arguments, strings.NewReader("{}"), &stdout); !errors.Is(err, ErrLiveRuntimeUnavailable) {
				t.Fatalf("expected unavailable runtime, got %v", err)
			}
			if stdout.Len() != 0 {
				t.Fatalf("refused command wrote output: %q", stdout.String())
			}
		})
	}
}

func TestCheckConfigDoesNotEchoMalformedSecretBearingInput(t *testing.T) {
	secret := "must-not-appear"
	var stdout bytes.Buffer
	err := runCheck(
		[]string{"--check-config"},
		strings.NewReader(
			`{"schema_version":2,"carrier_auth_version":1,"private_key":"`+secret+`"}`,
		),
		&stdout,
	)
	if !errors.Is(err, productionpeer.ErrInvalidConfig) {
		t.Fatalf("expected invalid configuration, got %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(stdout.String(), secret) {
		t.Fatal("malformed configuration was echoed")
	}
}

func TestCheckConfigRejectsAmbiguousDuplicateKeys(t *testing.T) {
	encoded, err := os.ReadFile("../../internal/productionpeer/testdata/valid-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := strings.Replace(
		string(encoded),
		`"peer_id": "peer.test.production",`,
		`"peer_id": "peer.test.production", "peer_id": "other.peer",`,
		1,
	)
	var stdout bytes.Buffer
	err = runCheck([]string{"--check-config"}, strings.NewReader(ambiguous), &stdout)
	if !errors.Is(err, productionpeer.ErrInvalidConfig) {
		t.Fatalf("expected duplicate-key refusal, got %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("ambiguous config wrote public success output: %q", stdout.String())
	}
}
