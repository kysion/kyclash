package vmexternalpeerlab

import (
	"bytes"
	"strings"
	"testing"
)

func testAppManifestV2() AppManifestV2 {
	return AppManifestV2{
		SchemaVersion:                AppManifestSchemaVersion,
		RuntimeTarget:                RuntimeTarget,
		ExecutablePath:               AppExecutablePath,
		ExpectedAuditUID:             501,
		ExecutableUID:                0,
		ExecutableMode:               0o755,
		ExecutableDevice:             1,
		ExecutableInode:              2,
		ExecutableSize:               32,
		ExecutableSHA256:             strings.Repeat("a", 64),
		AppTreeSHA256:                strings.Repeat("0", 64),
		AppTreeManifestSHA256:        strings.Repeat("9", 64),
		Architecture:                 "arm64",
		RunTicketExpectationSHA256:   strings.Repeat("b", 64),
		PeerConfigSHA256:             strings.Repeat("c", 64),
		CourierPublicKeySHA256:       strings.Repeat("d", 64),
		ClientListenerBaselineSHA256: strings.Repeat("e", 64),
		HarnessExecutableDevice:      3,
		HarnessExecutableInode:       4,
		HarnessExecutableSize:        32,
		HarnessExecutableSHA256:      strings.Repeat("f", 64),
	}
}

func TestAppManifestV2RoundTripAndStrictShape(t *testing.T) {
	manifest := testAppManifestV2()
	encoded, err := EncodeAppManifestV2(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAppManifestV2(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if decoded != manifest {
		t.Fatalf("manifest changed: %#v", decoded)
	}
	for name, mutate := range map[string]func(*AppManifestV2){
		"missing-app-tree": func(value *AppManifestV2) {
			value.AppTreeSHA256 = ""
		},
		"missing-app-tree-manifest": func(value *AppManifestV2) {
			value.AppTreeManifestSHA256 = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := manifest
			mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("required App tree pin was accepted empty")
			}
		})
	}
	duplicate := append(
		encoded[:len(encoded)-2],
		[]byte(`,"runtime_target":"kyclash-macos-lab-work"}`+"\n")...,
	)
	if _, err := DecodeAppManifestV2(bytes.NewReader(duplicate)); err == nil {
		t.Fatal("duplicate manifest key was accepted")
	}
	unknown := append(
		encoded[:len(encoded)-2],
		[]byte(`,"endpoint":"127.0.0.1"}`+"\n")...,
	)
	if _, err := DecodeAppManifestV2(bytes.NewReader(unknown)); err == nil {
		t.Fatal("unknown manifest field was accepted")
	}
}
