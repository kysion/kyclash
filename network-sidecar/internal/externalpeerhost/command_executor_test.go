package externalpeerhost

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
)

func TestFixedTartExecutableIsPathHashSizeAndIdentityBound(t *testing.T) {
	t.Parallel()
	t.Run("verified fixed repository path", func(t *testing.T) {
		path, data := createFakeTartExecutable(t)
		sum := sha256.Sum256(data)
		if err := verifyFixedTartExecutable(
			path,
			fmtHex(sum[:]),
			int64(len(data)),
		); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("hash and size mismatch", func(t *testing.T) {
		path, data := createFakeTartExecutable(t)
		sum := sha256.Sum256(data)
		if err := verifyFixedTartExecutable(
			path,
			fmtHex(sum[:]),
			int64(len(data)+1),
		); err == nil {
			t.Fatal("wrong Tart size was accepted")
		}
		if err := verifyFixedTartExecutable(
			path,
			fmtHex(make([]byte, sha256.Size)),
			int64(len(data)),
		); err == nil {
			t.Fatal("wrong Tart hash was accepted")
		}
	})
	t.Run("symlink refused", func(t *testing.T) {
		path, data := createFakeTartExecutable(t)
		sum := sha256.Sum256(data)
		target := filepath.Join(t.TempDir(), "tart")
		if err := os.WriteFile(target, data, 0o555); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := verifyFixedTartExecutable(
			path,
			fmtHex(sum[:]),
			int64(len(data)),
		); err == nil {
			t.Fatal("symlinked Tart executable was accepted")
		}
	})
	t.Run("replacement during hash refused", func(t *testing.T) {
		path, data := createFakeTartExecutable(t)
		sum := sha256.Sum256(data)
		old := path + ".old"
		err := verifyFixedTartExecutableWithHook(
			path,
			fmtHex(sum[:]),
			int64(len(data)),
			func() {
				if err := os.Rename(path, old); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0o555); err != nil {
					t.Fatal(err)
				}
			},
		)
		if err == nil {
			t.Fatal("Tart path replacement during hashing was accepted")
		}
	})
	t.Run("symlinked parent refused", func(t *testing.T) {
		path, data := createFakeTartExecutable(t)
		sum := sha256.Sum256(data)
		macos := filepath.Dir(path)
		real := macos + ".real"
		if err := os.Rename(macos, real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, macos); err != nil {
			t.Fatal(err)
		}
		if err := verifyFixedTartExecutable(
			path,
			fmtHex(sum[:]),
			int64(len(data)),
		); err == nil {
			t.Fatal("Tart executable beneath a symlinked parent was accepted")
		}
	})
}

func TestTartCommandNeverFallsBackToHomebrewOrPATH(t *testing.T) {
	t.Parallel()
	layout := testLayout(t)
	expected, err := fixedTartPath(layout)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(
		layout.RepositoryRoot,
		filepath.FromSlash(fixedTartRelativePath),
	)
	if expected != want {
		t.Fatalf("fixed Tart path=%q, want %q", expected, want)
	}
	executor, err := NewOSCommandExecutor(layout)
	if err != nil {
		t.Fatal(err)
	}
	_, err = executor.Run(context.Background(), CommandSpec{
		Purpose:          CommandTartARP,
		Executable:       "/opt/homebrew/bin/tart",
		Arguments:        []string{"ip", externalPeerClientVMName(), "--resolver=arp"},
		Environment:      append([]string(nil), fixedCommandEnvironment...),
		WorkingDirectory: "/",
		MaximumOutput:    128,
		Role:             "client",
	})
	if err == nil {
		t.Fatal("Homebrew Tart fallback was accepted")
	}
}

func TestFixedSSHCommandRejectsEveryMutableArgumentSurface(t *testing.T) {
	t.Parallel()
	valid, tartPath := validRemoteCommandSpec(t)
	if err := validateCommandSpec(valid, tartPath); err != nil {
		t.Fatal("valid fixed SSH command was refused")
	}
	indexOf := func(arguments []string, value string) int {
		t.Helper()
		for index, candidate := range arguments {
			if candidate == value {
				return index
			}
		}
		t.Fatalf("missing fixed argument %q", value)
		return -1
	}
	cases := map[string]func(*CommandSpec){
		"extra forwarding option": func(spec *CommandSpec) {
			insert := indexOf(spec.Arguments, "--")
			spec.Arguments = append(
				append(
					append([]string(nil), spec.Arguments[:insert]...),
					"-L", "127.0.0.1:1:127.0.0.1:22",
				),
				spec.Arguments[insert:]...,
			)
		},
		"extra port option": func(spec *CommandSpec) {
			insert := indexOf(spec.Arguments, "--")
			spec.Arguments = append(
				append(
					append([]string(nil), spec.Arguments[:insert]...),
					"-p", "22",
				),
				spec.Arguments[insert:]...,
			)
		},
		"changed proxy option": func(spec *CommandSpec) {
			spec.Arguments[indexOf(
				spec.Arguments,
				"ProxyCommand=none",
			)] = "ProxyCommand=/bin/sh"
		},
		"changed key path": func(spec *CommandSpec) {
			index := indexOf(spec.Arguments, "-i")
			spec.Arguments[index+1] = "/tmp/another-key"
		},
		"host port suffix": func(spec *CommandSpec) {
			index := indexOf(spec.Arguments, "--")
			spec.Arguments[index+1] += ":22"
		},
		"different private host": func(spec *CommandSpec) {
			index := indexOf(spec.Arguments, "--")
			spec.Arguments[index+1] = managementConsoleUser + "@192.168.64.99"
		},
		"remote shell suffix": func(spec *CommandSpec) {
			spec.Arguments[len(spec.Arguments)-1] += " ; '/bin/sh'"
		},
		"remote path mismatch": func(spec *CommandSpec) {
			spec.RemotePath = externalpeer.PeerPublicStatus
		},
		"remote parent mode mismatch": func(spec *CommandSpec) {
			values, err := parseFixedShellQuotedCommand(
				spec.Arguments[len(spec.Arguments)-1],
			)
			if err != nil {
				t.Fatal(err)
			}
			values[16] = "0755"
			quoted := make([]string, 0, len(values))
			for _, value := range values {
				quoted = append(quoted, shellQuote(value))
			}
			spec.Arguments[len(spec.Arguments)-1] = strings.Join(quoted, " ")
		},
	}
	for name, mutate := range cases {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			candidate := cloneCommandSpec(valid)
			mutate(&candidate)
			if validateCommandSpec(candidate, tartPath) == nil {
				t.Fatal("mutable SSH argument surface was accepted")
			}
		})
	}
}

func TestFixedShellQuotedCommandRoundTripsOnlyQuotedValues(t *testing.T) {
	t.Parallel()
	input := []string{
		"/usr/bin/python3",
		"-c",
		"line one\nvalue='fixed'\n",
		"",
	}
	quoted := make([]string, 0, len(input))
	for _, value := range input {
		quoted = append(quoted, shellQuote(value))
	}
	decoded, err := parseFixedShellQuotedCommand(strings.Join(quoted, " "))
	if err != nil || !equalStrings(decoded, input) {
		t.Fatal("fixed shell quoting did not round-trip")
	}
	for _, unsafe := range []string{
		"/usr/bin/python3",
		"'/usr/bin/python3' ; '/bin/sh'",
		"'/usr/bin/python3'  '-c'",
		"'/usr/bin/python3' '-c' trailing",
	} {
		if _, err := parseFixedShellQuotedCommand(unsafe); err == nil {
			t.Fatal("noncanonical shell command was accepted")
		}
	}
}

func validRemoteCommandSpec(t *testing.T) (CommandSpec, string) {
	t.Helper()
	layout := testLayout(t)
	tartPath := filepath.Join(
		layout.RepositoryRoot,
		filepath.FromSlash(fixedTartRelativePath),
	)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(
		make([]byte, sha256.Size),
	)
	role := roleContract{
		role: "client", vmName: externalpeer.ClientVMName,
		facts: externalpeer.CourierVMFacts{
			Role: "client", VMName: externalpeer.ClientVMName,
			PlatformUUID:       "11111111-2222-3333-4444-555555555555",
			SSHHostFingerprint: fingerprint,
			MAC:                [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
			IPv4:               [4]byte{192, 168, 64, 3},
		},
		consoleUID: 501,
		privateKey: filepath.Join(
			layout.Management,
			ClientManagementKeyName,
		),
		knownHosts: filepath.Join(
			layout.Management,
			ClientKnownHostsName,
		),
	}
	contract, err := lookupRemoteContract(
		role.consoleUID,
		role.role,
		filepath.Join(
			vmexternalpeerlab.ClientOutboxRoot,
			vmexternalpeerlab.ClientReadyName,
		),
		remoteActionRead,
	)
	if err != nil {
		t.Fatal(err)
	}
	address := netip.AddrFrom4(role.facts.IPv4)
	return CommandSpec{
		Purpose: CommandRemoteRead, Executable: fixedSSHPath,
		Arguments: sshArguments(
			role,
			address,
			buildRemoteCommand(
				role,
				contract,
				remoteActionRead,
				time.Unix(1_700_000_000, 0).UTC(),
			),
		),
		Environment:      append([]string(nil), fixedCommandEnvironment...),
		WorkingDirectory: "/",
		MaximumOutput:    contract.maximum + 4096,
		Role:             role.role,
		RemotePath:       contract.path,
	}, tartPath
}

func createFakeTartExecutable(t *testing.T) (string, []byte) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, filepath.FromSlash(fixedTartRelativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data := []byte("reviewed-tart-test-executable")
	if err := os.WriteFile(path, data, 0o555); err != nil {
		t.Fatal(err)
	}
	return path, data
}

func externalPeerClientVMName() string {
	return "kyclash-macos-lab-work"
}
