package externalpeerhost

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeergueststaging"
)

type buildInputFixture struct {
	layout           Layout
	binaryRun        string
	appRun           string
	binaryResult     binaryBuildResult
	binaryProvenance binaryBuildProvenance
}

func TestBuildInputsAndLayerAPublicationAreClosedAndReentrant(t *testing.T) {
	t.Parallel()
	fixture := prepareBuildInputFixture(t)
	prepareLayerAKeyAndPublicInputs(t, fixture.layout)
	if _, err := loadExternalPeerBuildInputs(fixture.layout); err != nil {
		t.Fatal(err)
	}
	if err := InitializeLayerAInputs(fixture.layout); err != nil {
		t.Fatal(err)
	}
	if err := InitializeLayerAInputs(fixture.layout); err != nil {
		t.Fatalf("identical create-only reentry failed: %v", err)
	}
	root := filepath.Join(fixture.layout.GuestShare, LayerAInputsName)
	assertDirectoryNames(t, root, []string{
		filepath.Base(externalpeergueststaging.ClientLayerAInput),
		filepath.Base(externalpeergueststaging.ClientSSHBootstrapInput),
		filepath.Base(externalpeergueststaging.PeerLayerAInput),
		filepath.Base(externalpeergueststaging.PeerSSHBootstrapInput),
	})
	client := filepath.Join(
		root,
		filepath.Base(externalpeergueststaging.ClientLayerAInput),
	)
	assertDirectoryNames(t, client, []string{
		"kyclash-vm-external-peer-lab-client-stage-layer-a",
		externalpeergueststaging.AppInputName,
		AppTreeManifestInputName,
		"kyclash-vm-external-peer-lab-supervisor",
		"kyclash-vm-external-peer-lab-harness",
		externalpeergueststaging.MihomoInputName,
		externalpeergueststaging.MihomoConfigInputName,
	})
	if err := validateNoPrivateKeyMaterial(root); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(client, AppTreeManifestInputName))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(
		filepath.Join(fixture.appRun, AppTreeManifestInputName),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifest, source) {
		t.Fatal("published App manifest was not the build-result-bound bytes")
	}
}

func TestLayerAPublicationRejectsTamperWithoutReplacement(t *testing.T) {
	t.Parallel()
	fixture := prepareBuildInputFixture(t)
	prepareLayerAKeyAndPublicInputs(t, fixture.layout)
	if err := InitializeLayerAInputs(fixture.layout); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(
		fixture.layout.GuestShare,
		LayerAInputsName,
		filepath.Base(externalpeergueststaging.ClientLayerAInput),
		"kyclash-vm-external-peer-lab-harness",
	)
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), before...)
	tampered[len(tampered)-1] ^= 1
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InitializeLayerAInputs(fixture.layout); err == nil {
		t.Fatal("published Layer A tamper was replaced instead of refused")
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, tampered) {
		t.Fatal("refusal path overwrote the pre-existing target")
	}
}

func TestBuildInputLoaderRejectsMissingSourceMismatchAndRoleSwap(t *testing.T) {
	t.Parallel()
	t.Run("missing result", func(t *testing.T) {
		fixture := prepareBuildInputFixture(t)
		if err := os.Remove(
			filepath.Join(fixture.binaryRun, "result.json"),
		); err != nil {
			t.Fatal(err)
		}
		if _, err := loadExternalPeerBuildInputs(fixture.layout); err == nil {
			t.Fatal("missing complete result was accepted")
		}
	})
	t.Run("cross-build source mismatch", func(t *testing.T) {
		fixture := prepareBuildInputFixture(t)
		path := filepath.Join(fixture.appRun, "result.json")
		var result appBuildResult
		readJSONTestFile(t, path, &result)
		result.Source.TreeSHA256 = repeatHex("f", 64)
		writeJSONTestFile(t, path, result)
		if _, err := loadExternalPeerBuildInputs(fixture.layout); err == nil {
			t.Fatal("binary/App source mismatch was accepted")
		}
	})
	t.Run("artifact role swap", func(t *testing.T) {
		fixture := prepareBuildInputFixture(t)
		fixture.binaryProvenance.Artifacts[0].Role = "peer"
		provenancePath := filepath.Join(fixture.binaryRun, "provenance.json")
		provenanceBytes := writeJSONTestFile(
			t,
			provenancePath,
			fixture.binaryProvenance,
		)
		fixture.binaryResult.ProvenanceSHA256 = hashBytes(provenanceBytes)
		writeJSONTestFile(
			t,
			filepath.Join(fixture.binaryRun, "result.json"),
			fixture.binaryResult,
		)
		if _, err := loadExternalPeerBuildInputs(fixture.layout); err == nil {
			t.Fatal("role-swapped build provenance was accepted")
		}
	})
}

func prepareBuildInputFixture(t *testing.T) buildInputFixture {
	t.Helper()
	layout := testLayout(t)
	source := buildSourceSnapshot{
		Commit:       "0123456789abcdef0123456789abcdef01234567",
		Dirty:        true,
		StatusSHA256: repeatHex("a", 64),
		TreeSHA256:   repeatHex("b", 64),
		FileCount:    42,
	}
	goIdentity := pinnedGoIdentity{
		RelativePath: pinnedGoRelativePath,
		ByteLength:   pinnedGoSize,
		SHA256:       pinnedGoSHA256,
		Version:      pinnedGoVersion,
	}
	binaryRun := filepath.Join(layout.BinaryBuildRoot, "run.fixture")
	if err := os.MkdirAll(binaryRun, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(layout.BinaryBuildRoot, 0o700); err != nil ||
		os.Chmod(binaryRun, 0o700) != nil {
		t.Fatal("failed to normalize binary fixture modes")
	}
	artifacts := make([]binaryArtifactRecord, 0, 14)
	hashLines := make([]byte, 0, 4096)
	for _, expected := range expectedBinaryArtifacts() {
		roleRoot := filepath.Join(binaryRun, expected.role)
		if err := os.MkdirAll(roleRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		payload := append(
			[]byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01},
			[]byte(expected.name)...,
		)
		path := filepath.Join(roleRoot, expected.name)
		if err := os.WriteFile(path, payload, 0o755); err != nil ||
			os.Chmod(path, 0o755) != nil {
			t.Fatal("failed to write Mach-O fixture")
		}
		record := binaryArtifactRecord{
			Artifact:      expected.name,
			Role:          expected.role,
			RuntimeTarget: expected.target,
			Source:        "network-sidecar/cmd/" + expected.name,
			GoTags:        append([]string(nil), expected.tags...),
			ByteLength:    uint64(len(payload)),
			SHA256:        hashBytes(payload),
		}
		artifacts = append(artifacts, record)
		hashLines = append(
			hashLines,
			[]byte(record.SHA256+"  "+expected.role+"/"+expected.name+"\n")...,
		)
	}
	mihomoPath := filepath.Join(
		layout.RepositoryRoot,
		"src-tauri",
		"sidecar",
		"verge-mihomo-aarch64-apple-darwin",
	)
	if err := os.MkdirAll(filepath.Dir(mihomoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	mihomo := append(
		[]byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01},
		[]byte("mihomo-fixture")...,
	)
	if err := os.WriteFile(mihomoPath, mihomo, 0o755); err != nil ||
		os.Chmod(mihomoPath, 0o755) != nil {
		t.Fatal("failed to write Mihomo fixture")
	}
	provenance := binaryBuildProvenance{
		SchemaVersion: 3,
		LabProfile:    "vm-external-peer",
		Status:        "complete",
		BuildTarget:   "host-build-only",
		Target:        "aarch64-apple-darwin",
		CGOEnabled:    false,
		ExecutionPolicy: "never-host; never-base; " +
			"client-only-kyclash-macos-lab-work; " +
			"peer-only-kyclash-macos-lab-peer",
		Source:      source,
		GoToolchain: goIdentity,
		GoEnvironmentAllowlist: map[string]string{
			"CGO_ENABLED": "0",
			"GO111MODULE": "on",
			"GOARCH":      "arm64",
			"GOARM64":     "v8.0",
			"GOAUTH":      "off",
			"GOCACHE": filepath.Join(
				layout.RepositoryRoot,
				"target",
				"macos-vm-lab",
				"cache",
				"external-peer-go-build",
			),
			"GOENV":      "off",
			"GOFLAGS":    "",
			"GOINSECURE": "",
			"GOMODCACHE": filepath.Join(
				layout.RepositoryRoot,
				"target",
				"macos-vm-lab",
				"cache",
				"external-peer-go-mod",
			),
			"GONOPROXY":   "",
			"GONOSUMDB":   "",
			"GOOS":        "darwin",
			"GOPRIVATE":   "",
			"GOPROXY":     "https://proxy.golang.org",
			"GOSUMDB":     "sum.golang.org",
			"GOTELEMETRY": "off",
			"GOTOOLCHAIN": "local",
			"GOVCS":       "*:off",
			"GOWORK":      "off",
		},
		GoBuildFlags: []string{
			"-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=",
		},
		MihomoInput:  "src-tauri/sidecar/verge-mihomo-aarch64-apple-darwin",
		MihomoSHA256: hashBytes(mihomo),
		Artifacts:    artifacts,
	}
	provenancePath := filepath.Join(binaryRun, "provenance.json")
	provenanceBytes := writeJSONTestFile(t, provenancePath, provenance)
	hashPath := filepath.Join(binaryRun, "sha256.txt")
	writeSecureTestFile(t, hashPath, hashLines)
	result := binaryBuildResult{
		SchemaVersion: 2,
		Status:        "complete",
		BuildTarget:   "host-build-only",
		RuntimeTargets: binaryRuntimeTargets{
			Client: "kyclash-macos-lab-work",
			Peer:   "kyclash-macos-lab-peer",
		},
		RunRoot:          binaryRun,
		Provenance:       provenancePath,
		ProvenanceSHA256: hashBytes(provenanceBytes),
		SHA256File:       hashPath,
		SHA256FileSHA256: hashBytes(hashLines),
		ArtifactCount:    len(artifacts),
		Source:           source,
		GoToolchain:      goIdentity,
	}
	writeJSONTestFile(t, filepath.Join(binaryRun, "result.json"), result)
	appRun := prepareAppBuildFixture(t, layout, source)
	prepareMihomoConfigFixture(t, layout)
	return buildInputFixture{
		layout:           layout,
		binaryRun:        binaryRun,
		appRun:           appRun,
		binaryResult:     result,
		binaryProvenance: provenance,
	}
}

func prepareAppBuildFixture(
	t *testing.T,
	layout Layout,
	source buildSourceSnapshot,
) string {
	t.Helper()
	appRun := filepath.Join(layout.AppBuildRoot, "run.fixture")
	app := filepath.Join(
		appRun,
		"cargo-target",
		"aarch64-apple-darwin",
		"release",
		"bundle",
		"macos",
		"KyClash.app",
	)
	for _, directory := range []string{
		app,
		filepath.Join(app, "Contents"),
		filepath.Join(app, "Contents", "MacOS"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil ||
			os.Chmod(directory, 0o755) != nil {
			t.Fatal("failed to create App fixture")
		}
	}
	if err := os.Chmod(layout.AppBuildRoot, 0o700); err != nil ||
		os.Chmod(appRun, 0o700) != nil {
		t.Fatal("failed to normalize App run modes")
	}
	infoBytes := []byte("fixture-info-plist")
	infoPath := filepath.Join(app, "Contents", "Info.plist")
	if err := os.WriteFile(infoPath, infoBytes, 0o644); err != nil ||
		os.Chmod(infoPath, 0o644) != nil {
		t.Fatal("failed to write Info.plist fixture")
	}
	executableBytes := append(
		[]byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01},
		[]byte("clash-verge-fixture")...,
	)
	executablePath := filepath.Join(app, "Contents", "MacOS", "clash-verge")
	if err := os.WriteFile(executablePath, executableBytes, 0o755); err != nil ||
		os.Chmod(executablePath, 0o755) != nil {
		t.Fatal("failed to write App executable fixture")
	}
	info := appInfoPlistRecord{
		RelativePath:     "Contents/Info.plist",
		BundleIdentifier: "net.kysion.kyclash",
		ShortVersion:     "2.5.3",
		BundleVersion:    "2.5.3",
		BundleExecutable: "clash-verge",
	}
	main := appExecutableRecord{
		RelativePath: "Contents/MacOS/clash-verge",
		Mode:         "0755",
		ByteLength:   uint64(len(executableBytes)),
		SHA256:       hashBytes(executableBytes),
	}
	infoDigest := hashBytes(infoBytes)
	mainDigest := hashBytes(executableBytes)
	entries := []appTreeEntry{
		{
			RelativePath: ".", Type: "directory", Mode: "0755",
			ByteLength: 0, SHA256: nil,
		},
		{
			RelativePath: "Contents", Type: "directory", Mode: "0755",
			ByteLength: 0, SHA256: nil,
		},
		{
			RelativePath: "Contents/Info.plist", Type: "file", Mode: "0644",
			ByteLength: uint64(len(infoBytes)), SHA256: &infoDigest,
		},
		{
			RelativePath: "Contents/MacOS", Type: "directory", Mode: "0755",
			ByteLength: 0, SHA256: nil,
		},
		{
			RelativePath: "Contents/MacOS/clash-verge",
			Type:         "file", Mode: "0755",
			ByteLength: uint64(len(executableBytes)), SHA256: &mainDigest,
		},
	}
	encodedEntries, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	treeSHA := hashBytes(encodedEntries)
	manifest := appTreeManifest{
		SchemaVersion:  1,
		AppName:        "KyClash.app",
		Source:         source,
		TreeSHA256:     treeSHA,
		InfoPlist:      info,
		MainExecutable: main,
		Entries:        entries,
	}
	manifestPath := filepath.Join(appRun, AppTreeManifestInputName)
	manifestBytes := writeJSONTestFile(t, manifestPath, manifest)
	provenance := appBuildProvenance{
		SchemaVersion:         1,
		Status:                "complete",
		BuildTarget:           "host-build-only",
		RuntimeExecution:      false,
		RuntimeTarget:         "kyclash-macos-lab-work",
		PeerTarget:            "kyclash-macos-lab-peer",
		RuntimeMode:           "vm_external_peer_lab",
		Feature:               "networking-vm-external-peer-lab-app",
		Target:                "aarch64-apple-darwin",
		Source:                source,
		App:                   app,
		AppTreeManifest:       manifestPath,
		AppTreeManifestSHA256: hashBytes(manifestBytes),
		AppTreeSHA256:         treeSHA,
		ExecutableSHA256:      main.SHA256,
		SigningIdentity:       nil,
		Packages:              false,
		UpdaterArtifacts:      false,
		EmbeddedPrivileged:    false,
	}
	provenancePath := filepath.Join(appRun, "provenance.json")
	provenanceBytes := writeJSONTestFile(t, provenancePath, provenance)
	result := appBuildResult{
		SchemaVersion:         2,
		Status:                "unsigned-disposable-vm-external-peer-lab-app",
		BuildTarget:           "host-build-only",
		RuntimeExecution:      false,
		RuntimeTarget:         "kyclash-macos-lab-work",
		PeerTarget:            "kyclash-macos-lab-peer",
		RuntimeMode:           "vm_external_peer_lab",
		Feature:               "networking-vm-external-peer-lab-app",
		Target:                "aarch64-apple-darwin",
		Source:                source,
		RunRoot:               appRun,
		App:                   app,
		AppTreeManifest:       manifestPath,
		AppTreeManifestSHA256: hashBytes(manifestBytes),
		AppTreeSHA256:         treeSHA,
		InfoPlist:             info,
		MainExecutable:        main,
		Provenance:            provenancePath,
		ProvenanceSHA256:      hashBytes(provenanceBytes),
		SigningIdentity:       nil,
		Packages:              false,
		UpdaterArtifacts:      false,
		EmbeddedPrivileged:    false,
	}
	writeJSONTestFile(t, filepath.Join(appRun, "result.json"), result)
	return appRun
}

func prepareMihomoConfigFixture(t *testing.T, layout Layout) {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate repository fixture")
	}
	repository := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", ".."))
	source := filepath.Join(
		repository,
		"macos",
		"route-helper",
		"vm-external-peer-lab-mihomo-config.json",
	)
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(
		layout.RepositoryRoot,
		"macos",
		"route-helper",
		"vm-external-peer-lab-mihomo-config.json",
	)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil ||
		os.WriteFile(target, data, 0o644) != nil ||
		os.Chmod(target, 0o644) != nil {
		t.Fatal("failed to copy checked-in Mihomo config fixture")
	}
}

func prepareLayerAKeyAndPublicInputs(t *testing.T, layout Layout) {
	t.Helper()
	if err := InitializeKeyStore(
		layout,
		bytes.NewReader(bytes.Repeat([]byte{0x31}, 64)),
	); err != nil {
		t.Fatal(err)
	}
	if err := InitializeManagementKeys(
		layout,
		bytes.NewReader(append(
			bytes.Repeat([]byte{0x32}, 32),
			bytes.Repeat([]byte{0x33}, 32)...,
		)),
	); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.GuestShare, 0o700); err != nil ||
		os.Chmod(layout.GuestShare, 0o700) != nil {
		t.Fatal("failed to create fixed guest share")
	}
}

func writeJSONTestFile(t *testing.T, path string, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil ||
		os.Chmod(path, 0o600) != nil {
		t.Fatal("failed to write JSON fixture")
	}
	return data
}

func readJSONTestFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}

func repeatHex(value string, length int) string {
	return string(bytes.Repeat([]byte(value), length))
}
