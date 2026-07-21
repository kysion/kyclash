//go:build darwin && kyclash_utun && kyclash_utun_lab

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/bootstrap"
	"github.com/kysion/kyclash/network-sidecar/internal/ipc"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"golang.org/x/crypto/curve25519"
)

const utunLabConfirmation = "authorized-kyclash-virtualization-framework-vm"

func TestRealUTUNStdinEOFAndMalformedIPCFinalAbsence(t *testing.T) {
	requireDisposableVirtualMac(t)
	for _, testCase := range []struct {
		name      string
		trailer   string
		wantError bool
	}{
		{name: "stdin_eof"},
		{name: "malformed_ipc", trailer: "{malformed\n", wantError: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			input := realUTUNInput(t, testCase.trailer)
			var output bytes.Buffer
			err := run(nil, strings.NewReader(input), &output)
			if testCase.wantError != (err != nil) {
				t.Fatalf("run error = %v, wantError %v", err, testCase.wantError)
			}
			interfaceName := preparedInterface(t, output.Bytes())
			if _, err := net.InterfaceByName(interfaceName); err == nil {
				t.Fatalf("owned interface %s remained after %s", interfaceName, testCase.name)
			}
		})
	}
}

func requireDisposableVirtualMac(t *testing.T) {
	t.Helper()
	if os.Getenv("KYCLASH_VM_LAB_CONFIRM") != utunLabConfirmation {
		t.Fatal("real utun lab requires the exact disposable-VM confirmation")
	}
	output, err := exec.Command("/usr/sbin/sysctl", "-n", "hw.model").Output()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(output)), "VirtualMac") {
		t.Fatal("real utun lab refuses non-VirtualMac hosts")
	}
}

func realUTUNInput(t *testing.T, trailer string) string {
	t.Helper()
	private := make([]byte, curve25519.ScalarSize)
	private[0], private[31] = 91, 64
	peerPrivate := make([]byte, curve25519.ScalarSize)
	peerPrivate[0], peerPrivate[31] = 101, 64
	peerPublic, err := curve25519.X25519(peerPrivate, curve25519.Basepoint)
	clear(peerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	config := bootstrap.Config{
		ProtocolVersion: bootstrap.ProtocolVersion,
		InstanceID:      "instance-utun-stdin",
		AuthToken:       bytes.Repeat([]byte{0x42}, 32),
		PrivateKey:      private,
	}
	networkProfile := profile.Profile{
		SchemaVersion: profile.SchemaVersion,
		ProfileID:     "utun.stdin.profile",
		ControlPlane:  "https://127.0.0.1/control",
		IdentityRef:   "keychain:net.kysion.kyclash.test.utun",
		Site:          profile.Site{ID: "utun-stdin", DisplayName: "utun stdin", PrivateCIDRs: []string{"10.90.0.2/32"}},
		Tunnel:        profile.Tunnel{LocalAddresses: []string{"10.90.0.1/24"}, PeerPublicKey: base64.StdEncoding.EncodeToString(peerPublic), KeepaliveSeconds: 5},
		Transports:    profile.Transports{Primary: profile.QUIC, Fallbacks: []profile.Transport{profile.WSS, profile.TCP}, Endpoints: []profile.Endpoint{{Transport: profile.QUIC, URL: "https://127.0.0.1:443"}, {Transport: profile.WSS, URL: "wss://127.0.0.1:443/kynp"}, {Transport: profile.TCP, URL: "tcp://127.0.0.1:443"}}},
		Policy:        profile.Policy{ConnectTimeoutSeconds: 5, HealthIntervalSeconds: 1, FallbackThreshold: 1},
	}
	clear(peerPublic)
	if err := networkProfile.Validate(); err != nil {
		t.Fatal(err)
	}
	profileData, err := json.Marshal(networkProfile)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapData, err := json.Marshal(config)
	config.Clear()
	if err != nil {
		t.Fatal(err)
	}
	requests := []ipc.Request{
		{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.stdin.profile", Payload: ipc.Payload{Type: "apply_profile", Data: profileData}},
		{ProtocolVersion: ipc.ProtocolVersion, RequestID: "request.stdin.prepare", Payload: ipc.Payload{Type: "prepare_tunnel"}},
	}
	var input strings.Builder
	input.Write(bootstrapData)
	input.WriteByte('\n')
	clear(bootstrapData)
	for _, request := range requests {
		encoded, marshalErr := json.Marshal(request)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		input.Write(encoded)
		input.WriteByte('\n')
		clear(encoded)
	}
	input.WriteString(trailer)
	return input.String()
}

func preparedInterface(t *testing.T, output []byte) string {
	t.Helper()
	for _, line := range bytes.Split(bytes.TrimSpace(output), []byte{'\n'}) {
		var response struct {
			RequestID string `json:"request_id"`
			Result    struct {
				OK struct {
					Type string                `json:"type"`
					Data ipc.TunnelDeviceFacts `json:"data"`
				} `json:"Ok"`
			} `json:"result"`
		}
		if json.Unmarshal(line, &response) == nil && response.Result.OK.Type == "tunnel_prepared" {
			if !strings.HasPrefix(response.Result.OK.Data.InterfaceName, "utun") {
				t.Fatal("prepare response did not contain a validated utun")
			}
			return response.Result.OK.Data.InterfaceName
		}
	}
	t.Fatal("missing tunnel_prepared response")
	return ""
}
