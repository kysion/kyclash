package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
)

func validManifest() appManifest {
	return appManifest{
		SchemaVersion:                appManifestSchemaVersion,
		RuntimeTarget:                vmexternalpeerlab.RuntimeTarget,
		ExecutablePath:               expectedAppExecutable,
		ExpectedAuditUID:             501,
		ExecutableUID:                0,
		ExecutableMode:               0o755,
		ExecutableDevice:             17,
		ExecutableInode:              29,
		ExecutableSize:               4096,
		ExecutableSHA256:             strings.Repeat("a", 64),
		AppTreeSHA256:                strings.Repeat("0", 64),
		AppTreeManifestSHA256:        strings.Repeat("9", 64),
		Architecture:                 "arm64",
		RunTicketExpectationSHA256:   strings.Repeat("b", 64),
		PeerConfigSHA256:             strings.Repeat("c", 64),
		CourierPublicKeySHA256:       strings.Repeat("d", 64),
		ClientListenerBaselineSHA256: strings.Repeat("e", 64),
		HarnessExecutableDevice:      31,
		HarnessExecutableInode:       37,
		HarnessExecutableSize:        8192,
		HarnessExecutableSHA256:      strings.Repeat("f", 64),
	}
}

func TestSupervisorRejectsArgumentsAndWrongRuntime(t *testing.T) {
	if err := validateArguments([]string{"--socket", "/tmp/caller"}); err == nil {
		t.Fatal("accepted caller-controlled arguments")
	}
	valid := runtimeFacts{
		GOOS: "darwin", GOARCH: "arm64", EffectiveUID: 0, ConsoleUID: 501,
		Model: "VirtualMac2,1", Runner: vmexternalpeerlab.RunnerEnv,
		Confirmation:  vmexternalpeerlab.VMConfirmation,
		RuntimeTarget: vmexternalpeerlab.RuntimeTarget,
	}
	if err := validateRuntimeFacts(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*runtimeFacts){
		"host":        func(facts *runtimeFacts) { facts.Model = "Mac15,6" },
		"rootless":    func(facts *runtimeFacts) { facts.EffectiveUID = 501 },
		"wrong-vm":    func(facts *runtimeFacts) { facts.RuntimeTarget = "kyclash-macos-lab-peer" },
		"unconfirmed": func(facts *runtimeFacts) { facts.Confirmation = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := valid
			mutate(&changed)
			if err := validateRuntimeFacts(changed); err == nil {
				t.Fatal("accepted invalid runtime facts")
			}
		})
	}
}

func TestAppManifestIsStrictAndPinsRootOwnedAppBytes(t *testing.T) {
	manifest := validManifest()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeAppManifest(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if decoded != manifest {
		t.Fatalf("manifest changed during decode: %#v", decoded)
	}
	for name, mutate := range map[string]func(*appManifest){
		"wrong-target":       func(value *appManifest) { value.RuntimeTarget = "host" },
		"wrong-path":         func(value *appManifest) { value.ExecutablePath = "/tmp/KyClash" },
		"caller-owned":       func(value *appManifest) { value.ExecutableUID = 501 },
		"writable":           func(value *appManifest) { value.ExecutableMode = 0o775 },
		"fat":                func(value *appManifest) { value.Architecture = "universal" },
		"uppercase-hash":     func(value *appManifest) { value.ExecutableSHA256 = strings.Repeat("A", 64) },
		"missing-ticket-pin": func(value *appManifest) { value.RunTicketExpectationSHA256 = "" },
		"missing-config-pin": func(value *appManifest) { value.PeerConfigSHA256 = "" },
		"missing-key-pin":    func(value *appManifest) { value.CourierPublicKeySHA256 = "" },
		"missing-listener-pin": func(value *appManifest) {
			value.ClientListenerBaselineSHA256 = ""
		},
		"missing-harness-identity": func(value *appManifest) {
			value.HarnessExecutableInode = 0
		},
		"missing-harness-hash": func(value *appManifest) {
			value.HarnessExecutableSHA256 = ""
		},
		"missing-app-tree-hash": func(value *appManifest) {
			value.AppTreeSHA256 = ""
		},
		"missing-app-tree-manifest-hash": func(value *appManifest) {
			value.AppTreeManifestSHA256 = ""
		},
		"root-process": func(value *appManifest) { value.ExpectedAuditUID = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := manifest
			mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("accepted invalid App manifest")
			}
		})
	}
	if _, err := decodeAppManifest(strings.NewReader(string(raw[:len(raw)-1]) + `,"endpoint":"127.0.0.1"}`)); err == nil {
		t.Fatal("accepted unknown authority in App manifest")
	}
	if _, err := decodeAppManifest(strings.NewReader(
		string(raw[:len(raw)-1]) + `,"runtime_target":"kyclash-macos-lab-work"}`,
	)); err == nil {
		t.Fatal("accepted duplicate App manifest key")
	}
}

func TestHarnessAndTicketExecutablePinsRejectReplacementHashAndSize(t *testing.T) {
	manifest := validManifest()
	if err := validateHarnessObservation(
		manifest,
		manifest.HarnessExecutableDevice,
		manifest.HarnessExecutableInode,
		manifest.HarnessExecutableSize,
		manifest.HarnessExecutableSHA256,
	); err != nil {
		t.Fatal(err)
	}
	for name, observed := range map[string]struct {
		device uint64
		inode  uint64
		size   uint64
		digest string
	}{
		"device-replacement": {
			manifest.HarnessExecutableDevice + 1,
			manifest.HarnessExecutableInode,
			manifest.HarnessExecutableSize,
			manifest.HarnessExecutableSHA256,
		},
		"inode-replacement": {
			manifest.HarnessExecutableDevice,
			manifest.HarnessExecutableInode + 1,
			manifest.HarnessExecutableSize,
			manifest.HarnessExecutableSHA256,
		},
		"size": {
			manifest.HarnessExecutableDevice,
			manifest.HarnessExecutableInode,
			manifest.HarnessExecutableSize + 1,
			manifest.HarnessExecutableSHA256,
		},
		"hash": {
			manifest.HarnessExecutableDevice,
			manifest.HarnessExecutableInode,
			manifest.HarnessExecutableSize,
			strings.Repeat("0", 64),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateHarnessObservation(
				manifest,
				observed.device,
				observed.inode,
				observed.size,
				observed.digest,
			); err == nil {
				t.Fatal("accepted changed harness executable")
			}
		})
	}

	payload := []byte("client executable")
	digest := sha256.Sum256(payload)
	digestHex := fmt.Sprintf("%x", digest[:])
	expectation := externalpeer.RunTicketExpectation{
		SchemaVersion: externalpeer.SchemaVersion,
		Files:         make([]externalpeer.ArtifactDigest, len(externalpeer.RunTicketArtifactNames)),
	}
	for index, name := range externalpeer.RunTicketArtifactNames {
		expectation.Files[index] = externalpeer.ArtifactDigest{
			Name: name, Length: 1, SHA256: strings.Repeat("1", 64),
		}
	}
	for index := range expectation.Files {
		if expectation.Files[index].Name == "client-supervisor" {
			expectation.Files[index].Length = uint64(len(payload))
			expectation.Files[index].SHA256 = digestHex
		}
	}
	if err := matchTicketExecutable(
		expectation,
		"client-supervisor",
		uint64(len(payload)),
		digestHex,
	); err != nil {
		t.Fatal(err)
	}
	if err := matchTicketExecutable(
		expectation,
		"client-supervisor",
		uint64(len(payload))+1,
		digestHex,
	); err == nil {
		t.Fatal("accepted changed ticket executable size")
	}
	if err := matchTicketExecutable(
		expectation,
		"client-supervisor",
		uint64(len(payload)),
		strings.Repeat("0", 64),
	); err == nil {
		t.Fatal("accepted changed ticket executable hash")
	}
}

func TestThinArm64ExecutableShapeIsExact(t *testing.T) {
	header := make([]byte, 32)
	copy(header[:4], []byte{0xcf, 0xfa, 0xed, 0xfe})
	copy(header[4:8], []byte{0x0c, 0x00, 0x00, 0x01})
	copy(header[12:16], []byte{0x02, 0x00, 0x00, 0x00})
	if err := validateThinArm64Executable(header); err != nil {
		t.Fatal(err)
	}
	for name, offset := range map[string]int{"fat": 0, "x86_64": 4, "dylib": 12} {
		t.Run(name, func(t *testing.T) {
			changed := append([]byte(nil), header...)
			changed[offset] ^= 0xff
			if err := validateThinArm64Executable(changed); err == nil {
				t.Fatal("accepted invalid Mach-O shape")
			}
		})
	}
}

func TestHarnessInvocationHasNoCallerAuthority(t *testing.T) {
	path, arguments, environment, directory := fixedHarnessInvocation()
	if path != vmexternalpeerlab.HarnessPath ||
		len(arguments) != 1 || arguments[0] != path ||
		len(environment) != 0 || directory != "/" {
		t.Fatalf("unsafe harness invocation: %q %#v %#v %q", path, arguments, environment, directory)
	}
	if childAppFD != 3 || childSupervisorFD != 4 {
		t.Fatal("inherited harness descriptor contract changed")
	}
}
