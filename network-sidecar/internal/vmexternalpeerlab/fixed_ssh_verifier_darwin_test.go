//go:build darwin && kyclash_utun && kyclash_vm_external_peer_lab

package vmexternalpeerlab

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"golang.org/x/crypto/ssh"
)

func fixedSSHTestArtifacts(t *testing.T) FixedSSHRunArtifacts {
	t.Helper()
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSSH, err := ssh.NewPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	overlayPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	overlaySSH, err := ssh.NewPublicKey(overlayPublic)
	if err != nil {
		t.Fatal(err)
	}
	systemPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	systemSSH, err := ssh.NewPublicKey(systemPublic)
	if err != nil {
		t.Fatal(err)
	}
	nonce := sha256.Sum256([]byte("fixed-ssh-verifier-test-nonce"))
	return FixedSSHRunArtifacts{
		OverlayClientPrivateKey: clientPrivate,
		OverlayClientPublicKey:  clientSSH.Marshal(),
		OverlayServerPublicKey:  overlaySSH.Marshal(),
		SystemSSHHostPublicKey:  systemSSH.Marshal(),
		RunNonceSHA256:          externalpeer.HashHex(nonce[:]),
	}
}

func fixedSSHShortTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/private/tmp", "kyclash-ssh-test.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(directory)
	})
	return directory
}

func fixedSSHVerifierForTest(
	t *testing.T,
	artifacts FixedSSHRunArtifacts,
) *FixedSSHVerifier {
	t.Helper()
	privateKey, clientPublic, overlayHost, systemHost, nonceHash, err :=
		validateFixedSSHArtifacts(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	return &FixedSSHVerifier{
		clientPrivate:  privateKey,
		clientPublic:   clientPublic,
		overlayHost:    overlayHost,
		systemHost:     systemHost,
		runNonceSHA256: nonceHash,
	}
}

func TestFixedSSHVerifierRequiresCanonicalRunArtifacts(t *testing.T) {
	artifacts := fixedSSHTestArtifacts(t)
	if _, _, _, _, _, err := validateFixedSSHArtifacts(artifacts); err != nil {
		t.Fatalf("valid artifacts rejected: %v", err)
	}
	mismatched := fixedSSHTestArtifacts(t)
	mismatched.OverlayClientPrivateKey = artifacts.OverlayClientPrivateKey
	if _, _, _, _, _, err := validateFixedSSHArtifacts(mismatched); !errors.Is(err, errFixedSSHProof) {
		t.Fatalf("mismatched client identity accepted: %v", err)
	}
	uppercase := artifacts
	uppercase.RunNonceSHA256 = strings.ToUpper(uppercase.RunNonceSHA256)
	if _, _, _, _, _, err := validateFixedSSHArtifacts(uppercase); !errors.Is(err, errFixedSSHProof) {
		t.Fatalf("non-canonical nonce hash accepted: %v", err)
	}
	extraPublic := artifacts
	extraPublic.SystemSSHHostPublicKey = append(extraPublic.SystemSSHHostPublicKey, 0)
	if _, _, _, _, _, err := validateFixedSSHArtifacts(extraPublic); !errors.Is(err, errFixedSSHProof) {
		t.Fatalf("non-canonical host key accepted: %v", err)
	}
}

func TestFixedSSHVerifierRunsSystemProofOnlyWhenRequired(t *testing.T) {
	artifacts := fixedSSHTestArtifacts(t)
	verifier := fixedSSHVerifierForTest(t, artifacts)
	var overlayCalls int
	var systemCalls int
	dialMarker := errors.New("dial marker")
	verifier.dialFactory = func(tunnelInterface string) (externalpeer.OverlayDialContext, error) {
		if tunnelInterface != "utun17" {
			t.Fatalf("unexpected tunnel: %q", tunnelInterface)
		}
		return func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "marker" || address != "marker" {
				t.Fatalf("unexpected marker dial: %s %s", network, address)
			}
			return nil, dialMarker
		}, nil
	}
	verifier.overlayProbe = func(
		_ context.Context,
		address string,
		privateKey ed25519.PrivateKey,
		hostPublic []byte,
		nonceHash string,
		dial externalpeer.OverlayDialContext,
	) error {
		overlayCalls++
		if address != OverlaySSH ||
			!bytes.Equal(privateKey, verifier.clientPrivate) ||
			!bytes.Equal(hostPublic, verifier.overlayHost) ||
			nonceHash != string(verifier.runNonceSHA256) {
			t.Fatal("overlay proof received mutable authority")
		}
		if _, err := dial(context.Background(), "marker", "marker"); !errors.Is(err, dialMarker) {
			t.Fatalf("unexpected dial marker: %v", err)
		}
		return nil
	}
	verifier.systemProbe = func(_ context.Context, tunnelInterface string) error {
		systemCalls++
		if tunnelInterface != "utun17" {
			t.Fatalf("unexpected system tunnel: %q", tunnelInterface)
		}
		return nil
	}

	quic, err := verifier.VerifySSH(context.Background(), "utun17", false)
	if err != nil || !quic.InProcessVerified || quic.SystemVerified {
		t.Fatalf("unexpected QUIC/WSS proof: %#v %v", quic, err)
	}
	tcp, err := verifier.VerifySSH(context.Background(), "utun17", true)
	if err != nil || !tcp.InProcessVerified || !tcp.SystemVerified {
		t.Fatalf("unexpected TCP proof: %#v %v", tcp, err)
	}
	if overlayCalls != 2 || systemCalls != 1 {
		t.Fatalf("unexpected proof counts: overlay=%d system=%d", overlayCalls, systemCalls)
	}
	if _, err := verifier.VerifySSH(context.Background(), MihomoInterface, false); !errors.Is(err, errFixedSSHProof) {
		t.Fatalf("Mihomo interface was accepted: %v", err)
	}
	if err := verifier.Close(); err != nil {
		t.Fatal(err)
	}
	if verifier.clientPrivate != nil ||
		verifier.clientPublic != nil ||
		verifier.overlayHost != nil ||
		verifier.systemHost != nil ||
		verifier.runNonceSHA256 != nil {
		t.Fatal("Close retained run-bound SSH artifacts")
	}
	if _, err := verifier.VerifySSH(context.Background(), "utun17", false); !errors.Is(err, errFixedSSHProof) {
		t.Fatalf("closed verifier accepted a proof: %v", err)
	}
}

func TestFixedSystemSSHArgumentsAreClosedAndInterfaceBound(t *testing.T) {
	expected := []string{
		"-4", "-F", "/dev/null",
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ChallengeResponseAuthentication=no",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PubkeyAuthentication=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=" + fixedSSHAgentSocketPath,
		"-o", "IdentityFile=" + fixedSSHIdentityPath,
		"-o", "UserKnownHostsFile=" + fixedSSHKnownHostsPath,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "HostKeyAlgorithms=ssh-ed25519",
		"-o", "PubkeyAcceptedAlgorithms=ssh-ed25519",
		"-o", "DisableForwarding=yes",
		"-o", "ClearAllForwardings=yes",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "Tunnel=no",
		"-o", "PermitLocalCommand=no",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "ControlPersist=no",
		"-o", "ProxyCommand=none",
		"-o", "ProxyJump=none",
		"-o", "RequestTTY=no",
		"-o", "ConnectionAttempts=1",
		"-o", "ConnectTimeout=10",
		"-o", "NumberOfPasswordPrompts=0",
		"-o", "LogLevel=ERROR",
		"-B", "utun17",
		"-b", "10.88.0.1",
		"-p", "2222",
		"-l", fixedSSHRestrictedUser,
		"-T",
		"10.88.0.2",
		externalpeer.ForcedCommandName,
	}
	if actual := fixedSystemSSHArguments("utun17"); !slices.Equal(actual, expected) {
		t.Fatalf("system SSH argv drifted:\nactual: %#v\nexpected: %#v", actual, expected)
	}
}

func TestAppleSSHInspectionUsesExactAppleRequirement(t *testing.T) {
	expected := []string{
		"-v",
		"--strict",
		"--verbose=4",
		"-R=anchor apple",
		appleSSHPath,
	}
	if actual := fixedAppleCodeSignArguments(); !slices.Equal(actual, expected) {
		t.Fatalf("codesign argv drifted: %#v", actual)
	}
}

func TestSingleUseAgentOffersOneKeyAndSignsAtMostOnce(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	one := &singleUseAgent{signer: signer}
	keys, err := one.List()
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Marshal(), signer.PublicKey().Marshal()) {
		t.Fatalf("unexpected agent identity: %#v %v", keys, err)
	}
	data := []byte("one signature only")
	signature, err := one.Sign(signer.PublicKey(), data)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := sshPublic.Verify(data, signature); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
	if _, err := one.Sign(signer.PublicKey(), data); !errors.Is(err, errFixedSSHProof) {
		t.Fatalf("second signature was accepted: %v", err)
	}
	if one.signatureCount() != 1 {
		t.Fatalf("unexpected signature count: %d", one.signatureCount())
	}
	if err := one.RemoveAll(); !errors.Is(err, errFixedSSHProof) {
		t.Fatalf("agent mutation was accepted: %v", err)
	}
	if _, err := one.Signers(); !errors.Is(err, errFixedSSHProof) {
		t.Fatalf("agent signer extraction was accepted: %v", err)
	}
}

func TestFixedSSHWorkspaceIsExclusivePublicOnlyAndRemoved(t *testing.T) {
	artifacts := fixedSSHTestArtifacts(t)
	stateRoot := fixedSSHShortTempDir(t)
	if err := os.Chmod(stateRoot, fixedSSHStateRootMode); err != nil {
		t.Fatal(err)
	}
	proofRoot := filepath.Join(stateRoot, "proof")
	workspace, err := createFixedSSHWorkspaceAt(
		stateRoot,
		proofRoot,
		uint32(os.Geteuid()),
		fixedSSHStateRootMode,
		artifacts.OverlayClientPublicKey,
		artifacts.SystemSSHHostPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity.pub", "known_hosts"} {
		path := filepath.Join(proofRoot, name)
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != fixedSSHPublicFileMode {
			t.Fatalf("unsafe public artifact mode: %s %o", path, info.Mode().Perm())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, artifacts.OverlayClientPrivateKey) {
			clear(data)
			t.Fatalf("private key bytes reached %s", path)
		}
		clear(data)
	}
	if _, err := createFixedSSHWorkspaceAt(
		stateRoot,
		proofRoot,
		uint32(os.Geteuid()),
		fixedSSHStateRootMode,
		artifacts.OverlayClientPublicKey,
		artifacts.SystemSSHHostPublicKey,
	); !errors.Is(err, errFixedSSHProof) {
		t.Fatalf("second O_EXCL workspace was accepted: %v", err)
	}
	if err := workspace.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(proofRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace survived cleanup: %v", err)
	}
}

func TestAgentSocketRejectsAnythingButAuthorizedPID(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = publicKey
	socketPath := filepath.Join(fixedSSHShortTempDir(t), "agent.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := startBoundAgentServer(listener, &singleUseAgent{signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := server.authorizePID(os.Getpid() + 100_000); err != nil {
		t.Fatal(err)
	}
	if err := server.wait(); !errors.Is(err, errFixedSSHProof) {
		t.Fatalf("wrong PID reached the agent: %v", err)
	}
	if err := server.close(); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentTaggedTestBinaryContainsArm64MachO(t *testing.T) {
	file, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := requireArm64MachO(file); err != nil {
		t.Fatalf("tagged test binary was not arm64 Mach-O: %v", err)
	}
}
