package externalpeerhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	pinnedGoRelativePath = "target/toolchains/go1.26.5/bin/go"
	pinnedGoSize         = uint64(14500160)
	pinnedGoSHA256       = "3925fc3221ac440ebf7c35361ff663bed0c7bdb2e0a157b75fe993607ffe0a19"
	pinnedGoVersion      = "go version go1.26.5 darwin/arm64"
)

type buildSourceSnapshot struct {
	Commit       string `json:"commit"`
	Dirty        bool   `json:"dirty"`
	StatusSHA256 string `json:"status_sha256"`
	TreeSHA256   string `json:"tree_sha256"`
	FileCount    int    `json:"file_count"`
}

func (value buildSourceSnapshot) validate() error {
	if len(value.Commit) != 40 ||
		!validLowerHex(value.Commit) ||
		!validLowerSHA256(value.StatusSHA256) ||
		!validLowerSHA256(value.TreeSHA256) ||
		value.FileCount <= 0 {
		return ErrUnsafeHostCourier
	}
	return nil
}

type pinnedGoIdentity struct {
	RelativePath string `json:"relative_path"`
	ByteLength   uint64 `json:"byte_length"`
	SHA256       string `json:"sha256"`
	Version      string `json:"version"`
}

func (value pinnedGoIdentity) validate() error {
	if value.RelativePath != pinnedGoRelativePath ||
		value.ByteLength != pinnedGoSize ||
		value.SHA256 != pinnedGoSHA256 ||
		value.Version != pinnedGoVersion {
		return ErrUnsafeHostCourier
	}
	return nil
}

type binaryRuntimeTargets struct {
	Client string `json:"client"`
	Peer   string `json:"peer"`
}

type binaryBuildResult struct {
	SchemaVersion    uint8                `json:"schema_version"`
	Status           string               `json:"status"`
	BuildTarget      string               `json:"build_target"`
	RuntimeTargets   binaryRuntimeTargets `json:"runtime_targets"`
	RunRoot          string               `json:"run_root"`
	Provenance       string               `json:"provenance"`
	ProvenanceSHA256 string               `json:"provenance_sha256"`
	SHA256File       string               `json:"sha256"`
	SHA256FileSHA256 string               `json:"sha256_file_sha256"`
	ArtifactCount    int                  `json:"artifact_count"`
	Source           buildSourceSnapshot  `json:"source"`
	GoToolchain      pinnedGoIdentity     `json:"go_toolchain"`
}

type binaryArtifactRecord struct {
	Artifact      string   `json:"artifact"`
	Role          string   `json:"role"`
	RuntimeTarget string   `json:"runtime_target"`
	Source        string   `json:"source"`
	GoTags        []string `json:"go_tags"`
	ByteLength    uint64   `json:"byte_length"`
	SHA256        string   `json:"sha256"`
}

type binaryBuildProvenance struct {
	SchemaVersion          uint8                  `json:"schema_version"`
	LabProfile             string                 `json:"lab_profile"`
	Status                 string                 `json:"status"`
	BuildTarget            string                 `json:"build_target"`
	Target                 string                 `json:"target"`
	CGOEnabled             bool                   `json:"cgo_enabled"`
	ExecutionPolicy        string                 `json:"execution_policy"`
	Source                 buildSourceSnapshot    `json:"source"`
	GoToolchain            pinnedGoIdentity       `json:"go_toolchain"`
	GoEnvironmentAllowlist map[string]string      `json:"go_environment_allowlist"`
	GoBuildFlags           []string               `json:"go_build_flags"`
	MihomoInput            string                 `json:"mihomo_input"`
	MihomoSHA256           string                 `json:"mihomo_sha256"`
	Artifacts              []binaryArtifactRecord `json:"artifacts"`
}

type appInfoPlistRecord struct {
	RelativePath     string `json:"relative_path"`
	BundleIdentifier string `json:"bundle_identifier"`
	ShortVersion     string `json:"short_version"`
	BundleVersion    string `json:"bundle_version"`
	BundleExecutable string `json:"bundle_executable"`
}

type appExecutableRecord struct {
	RelativePath string `json:"relative_path"`
	Mode         string `json:"mode"`
	ByteLength   uint64 `json:"byte_length"`
	SHA256       string `json:"sha256"`
}

type appTreeEntry struct {
	RelativePath string  `json:"relative_path"`
	Type         string  `json:"type"`
	Mode         string  `json:"mode"`
	ByteLength   uint64  `json:"byte_length"`
	SHA256       *string `json:"sha256"`
}

type appTreeManifest struct {
	SchemaVersion  uint8               `json:"schema_version"`
	AppName        string              `json:"app_name"`
	Source         buildSourceSnapshot `json:"source"`
	TreeSHA256     string              `json:"tree_sha256"`
	InfoPlist      appInfoPlistRecord  `json:"info_plist"`
	MainExecutable appExecutableRecord `json:"main_executable"`
	Entries        []appTreeEntry      `json:"entries"`
}

type appBuildResult struct {
	SchemaVersion         uint8               `json:"schema_version"`
	Status                string              `json:"status"`
	BuildTarget           string              `json:"build_target"`
	RuntimeExecution      bool                `json:"runtime_execution_performed"`
	RuntimeTarget         string              `json:"runtime_target"`
	PeerTarget            string              `json:"peer_target"`
	RuntimeMode           string              `json:"runtime_mode"`
	Feature               string              `json:"feature"`
	Target                string              `json:"target"`
	Source                buildSourceSnapshot `json:"source"`
	RunRoot               string              `json:"run_root"`
	App                   string              `json:"app"`
	AppTreeManifest       string              `json:"app_tree_manifest"`
	AppTreeManifestSHA256 string              `json:"app_tree_manifest_sha256"`
	AppTreeSHA256         string              `json:"app_tree_sha256"`
	InfoPlist             appInfoPlistRecord  `json:"info_plist"`
	MainExecutable        appExecutableRecord `json:"main_executable"`
	Provenance            string              `json:"provenance"`
	ProvenanceSHA256      string              `json:"provenance_sha256"`
	SigningIdentity       *string             `json:"signing_identity"`
	Packages              bool                `json:"packages"`
	UpdaterArtifacts      bool                `json:"updater_artifacts"`
	EmbeddedPrivileged    bool                `json:"embedded_privileged_payloads"`
}

type appBuildProvenance struct {
	SchemaVersion         uint8               `json:"schema_version"`
	Status                string              `json:"status"`
	BuildTarget           string              `json:"build_target"`
	RuntimeExecution      bool                `json:"runtime_execution_performed"`
	RuntimeTarget         string              `json:"runtime_target"`
	PeerTarget            string              `json:"peer_target"`
	RuntimeMode           string              `json:"runtime_mode"`
	Feature               string              `json:"feature"`
	Target                string              `json:"target"`
	Source                buildSourceSnapshot `json:"source"`
	App                   string              `json:"app"`
	AppTreeManifest       string              `json:"app_tree_manifest"`
	AppTreeManifestSHA256 string              `json:"app_tree_manifest_sha256"`
	AppTreeSHA256         string              `json:"app_tree_sha256"`
	ExecutableSHA256      string              `json:"executable_sha256"`
	SigningIdentity       *string             `json:"signing_identity"`
	Packages              bool                `json:"packages"`
	UpdaterArtifacts      bool                `json:"updater_artifacts"`
	EmbeddedPrivileged    bool                `json:"embedded_privileged_payloads"`
}

type externalPeerBuildInputs struct {
	source            buildSourceSnapshot
	binaryRunRoot     string
	appRunRoot        string
	artifacts         map[string]binaryArtifactRecord
	artifactPaths     map[string]string
	appPath           string
	appManifestPath   string
	appManifestSize   uint64
	appManifestSHA256 string
	appManifest       appTreeManifest
	mihomoSHA256      string
}

func loadExternalPeerBuildInputs(layout Layout) (externalPeerBuildInputs, error) {
	binaryRun, err := findSingleCompleteRun(layout.BinaryBuildRoot)
	if err != nil {
		return externalPeerBuildInputs{}, err
	}
	appRun, err := findSingleCompleteRun(layout.AppBuildRoot)
	if err != nil {
		return externalPeerBuildInputs{}, err
	}
	binaryResultBytes, err := readOwnedRegularFile(
		filepath.Join(binaryRun, "result.json"),
		secureFileMode,
		2*1024*1024,
	)
	if err != nil {
		return externalPeerBuildInputs{}, err
	}
	defer clear(binaryResultBytes)
	var binaryResult binaryBuildResult
	if decodeStrictJSON(binaryResultBytes, &binaryResult) != nil ||
		binaryResult.SchemaVersion != 2 ||
		binaryResult.Status != "complete" ||
		binaryResult.BuildTarget != "host-build-only" ||
		binaryResult.RuntimeTargets.Client != "kyclash-macos-lab-work" ||
		binaryResult.RuntimeTargets.Peer != "kyclash-macos-lab-peer" ||
		binaryResult.RunRoot != binaryRun ||
		binaryResult.Provenance != filepath.Join(binaryRun, "provenance.json") ||
		binaryResult.SHA256File != filepath.Join(binaryRun, "sha256.txt") ||
		binaryResult.ArtifactCount != 14 ||
		binaryResult.Source.validate() != nil ||
		binaryResult.GoToolchain.validate() != nil {
		return externalPeerBuildInputs{}, ErrUnsafeHostCourier
	}
	provenanceBytes, err := readOwnedRegularFile(
		binaryResult.Provenance,
		secureFileMode,
		4*1024*1024,
	)
	if err != nil {
		return externalPeerBuildInputs{}, err
	}
	defer clear(provenanceBytes)
	hashesBytes, err := readOwnedRegularFile(
		binaryResult.SHA256File,
		secureFileMode,
		128*1024,
	)
	if err != nil {
		return externalPeerBuildInputs{}, err
	}
	defer clear(hashesBytes)
	if hashBytes(provenanceBytes) != binaryResult.ProvenanceSHA256 ||
		hashBytes(hashesBytes) != binaryResult.SHA256FileSHA256 {
		return externalPeerBuildInputs{}, ErrUnsafeHostCourier
	}
	var binaryProvenance binaryBuildProvenance
	if decodeStrictJSON(provenanceBytes, &binaryProvenance) != nil ||
		validateBinaryProvenance(
			binaryProvenance,
			binaryResult.Source,
			layout.RepositoryRoot,
		) != nil {
		return externalPeerBuildInputs{}, ErrUnsafeHostCourier
	}
	artifacts := make(map[string]binaryArtifactRecord, len(binaryProvenance.Artifacts))
	artifactPaths := make(map[string]string, len(binaryProvenance.Artifacts))
	hashLines := make([]string, 0, len(binaryProvenance.Artifacts))
	for _, artifact := range binaryProvenance.Artifacts {
		if _, exists := artifacts[artifact.Artifact]; exists {
			return externalPeerBuildInputs{}, ErrUnsafeHostCourier
		}
		output := filepath.Join(binaryRun, artifact.Role, artifact.Artifact)
		if validateBuiltExecutable(output, artifact) != nil {
			return externalPeerBuildInputs{}, ErrUnsafeHostCourier
		}
		artifacts[artifact.Artifact] = artifact
		artifactPaths[artifact.Artifact] = output
		hashLines = append(
			hashLines,
			artifact.SHA256+"  "+artifact.Role+"/"+artifact.Artifact,
		)
	}
	if string(hashesBytes) != strings.Join(hashLines, "\n")+"\n" {
		return externalPeerBuildInputs{}, ErrUnsafeHostCourier
	}

	appResultBytes, err := readOwnedRegularFile(
		filepath.Join(appRun, "result.json"),
		secureFileMode,
		2*1024*1024,
	)
	if err != nil {
		return externalPeerBuildInputs{}, err
	}
	defer clear(appResultBytes)
	var appResult appBuildResult
	if decodeStrictJSON(appResultBytes, &appResult) != nil ||
		validateAppResult(appResult, appRun, binaryResult.Source) != nil {
		return externalPeerBuildInputs{}, ErrUnsafeHostCourier
	}
	appProvenanceBytes, err := readOwnedRegularFile(
		appResult.Provenance,
		secureFileMode,
		2*1024*1024,
	)
	if err != nil {
		return externalPeerBuildInputs{}, err
	}
	defer clear(appProvenanceBytes)
	manifestBytes, err := readOwnedRegularFile(
		appResult.AppTreeManifest,
		secureFileMode,
		8*1024*1024,
	)
	if err != nil {
		return externalPeerBuildInputs{}, err
	}
	defer clear(manifestBytes)
	if hashBytes(appProvenanceBytes) != appResult.ProvenanceSHA256 ||
		hashBytes(manifestBytes) != appResult.AppTreeManifestSHA256 {
		return externalPeerBuildInputs{}, ErrUnsafeHostCourier
	}
	var appProvenance appBuildProvenance
	var manifest appTreeManifest
	if decodeStrictJSON(appProvenanceBytes, &appProvenance) != nil ||
		decodeStrictJSON(manifestBytes, &manifest) != nil ||
		validateAppProvenance(appProvenance, appResult) != nil ||
		validateAppTreeManifest(appResult.App, manifest, appResult) != nil {
		return externalPeerBuildInputs{}, ErrUnsafeHostCourier
	}
	return externalPeerBuildInputs{
		source: binaryResult.Source, binaryRunRoot: binaryRun,
		appRunRoot: appRun, artifacts: artifacts,
		artifactPaths: artifactPaths, appPath: appResult.App,
		appManifestPath:   appResult.AppTreeManifest,
		appManifestSize:   uint64(len(manifestBytes)),
		appManifestSHA256: appResult.AppTreeManifestSHA256,
		appManifest:       manifest, mihomoSHA256: binaryProvenance.MihomoSHA256,
	}, nil
}

func findSingleCompleteRun(parent string) (string, error) {
	uid := uint32(os.Getuid())
	info, err := os.Lstat(parent)
	if err != nil || !safeBuildDirectory(info, uid) {
		return "", ErrUnsafeHostCourier
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return "", ErrUnsafeHostCourier
	}
	var result string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "run.") {
			continue
		}
		run := filepath.Join(parent, entry.Name())
		runInfo, err := os.Lstat(run)
		if err != nil || !safeDirectoryInfo(runInfo, uid) {
			return "", ErrUnsafeHostCourier
		}
		resultPath := filepath.Join(run, "result.json")
		if _, err := os.Lstat(resultPath); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", ErrUnsafeHostCourier
		}
		if result != "" {
			return "", ErrUnsafeHostCourier
		}
		result = run
	}
	if result == "" {
		return "", ErrUnsafeHostCourier
	}
	return result, nil
}

func validateBinaryProvenance(
	value binaryBuildProvenance,
	source buildSourceSnapshot,
	repositoryRoot string,
) error {
	expectedNames := expectedBinaryArtifacts()
	if value.SchemaVersion != 3 ||
		value.LabProfile != "vm-external-peer" ||
		value.Status != "complete" ||
		value.BuildTarget != "host-build-only" ||
		value.Target != "aarch64-apple-darwin" ||
		value.CGOEnabled ||
		value.ExecutionPolicy !=
			"never-host; never-base; client-only-kyclash-macos-lab-work; "+
				"peer-only-kyclash-macos-lab-peer" ||
		value.Source != source ||
		value.GoToolchain.validate() != nil ||
		value.MihomoInput !=
			"src-tauri/sidecar/verge-mihomo-aarch64-apple-darwin" ||
		!validLowerSHA256(value.MihomoSHA256) ||
		len(value.Artifacts) != len(expectedNames) ||
		validateGoEnvironment(
			value.GoEnvironmentAllowlist,
			repositoryRoot,
		) != nil ||
		!equalStrings(value.GoBuildFlags, []string{
			"-mod=readonly",
			"-trimpath",
			"-buildvcs=false",
			"-ldflags=-buildid=",
		}) {
		return ErrUnsafeHostCourier
	}
	for index, artifact := range value.Artifacts {
		expected := expectedNames[index]
		if artifact.Artifact != expected.name ||
			artifact.Role != expected.role ||
			artifact.RuntimeTarget != expected.target ||
			artifact.Source != "network-sidecar/cmd/"+expected.name ||
			!equalStrings(artifact.GoTags, expected.tags) ||
			artifact.ByteLength < 8 ||
			!validLowerSHA256(artifact.SHA256) {
			return ErrUnsafeHostCourier
		}
	}
	return nil
}

type expectedArtifact struct {
	role   string
	name   string
	target string
	tags   []string
}

func expectedBinaryArtifacts() []expectedArtifact {
	client := "kyclash-macos-lab-work"
	peer := "kyclash-macos-lab-peer"
	clientTags := []string{
		"kyclash_utun",
		"kyclash_vm_external_peer_lab",
	}
	return []expectedArtifact{
		{"client", "kyclash-vm-external-peer-lab-client-stage-layer-a", client, nil},
		{"client", "kyclash-vm-external-peer-lab-client-bootstrap-ssh-layer-a", client, nil},
		{"client", "kyclash-vm-external-peer-lab-client-prepare-layer-b", client, nil},
		{"client", "kyclash-vm-external-peer-lab-client-pin-layer-b", client, nil},
		{"client", "kyclash-vm-external-peer-lab-supervisor", client, clientTags},
		{"client", "kyclash-vm-external-peer-lab-harness", client, clientTags},
		{"peer", "kyclash-vm-external-peer-lab-peer-stage-layer-a", peer, nil},
		{"peer", "kyclash-vm-external-peer-lab-peer-bootstrap-ssh-layer-a", peer, nil},
		{"peer", "kyclash-vm-external-peer-lab-peer-prepare-layer-b", peer, nil},
		{"peer", "kyclash-vm-external-peer-lab-peer-pin-layer-b", peer, nil},
		{"peer", "kyclash-vm-external-peer-lab-peer-root-supervisor", peer, nil},
		{"peer", "kyclash-vm-external-peer-lab-peer", peer, nil},
		{"peer", "kyclash-vm-external-peer-lab-listener-auditor", peer, nil},
		{"peer", "kyclash-vm-external-peer-lab-forced-command", peer, nil},
	}
}

func validateGoEnvironment(
	value map[string]string,
	repositoryRoot string,
) error {
	expected := map[string]string{
		"CGO_ENABLED": "0",
		"GO111MODULE": "on",
		"GOARCH":      "arm64",
		"GOARM64":     "v8.0",
		"GOAUTH":      "off",
		"GOCACHE": filepath.Join(
			repositoryRoot,
			"target",
			"macos-vm-lab",
			"cache",
			"external-peer-go-build",
		),
		"GOENV":      "off",
		"GOFLAGS":    "",
		"GOINSECURE": "",
		"GOMODCACHE": filepath.Join(
			repositoryRoot,
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
	}
	if len(value) != len(expected) {
		return ErrUnsafeHostCourier
	}
	for name, expectedValue := range expected {
		if value[name] != expectedValue {
			return ErrUnsafeHostCourier
		}
	}
	return nil
}

func validateAppResult(
	value appBuildResult,
	runRoot string,
	source buildSourceSnapshot,
) error {
	if value.SchemaVersion != 2 ||
		value.Status != "unsigned-disposable-vm-external-peer-lab-app" ||
		value.BuildTarget != "host-build-only" ||
		value.RuntimeExecution ||
		value.RuntimeTarget != "kyclash-macos-lab-work" ||
		value.PeerTarget != "kyclash-macos-lab-peer" ||
		value.RuntimeMode != "vm_external_peer_lab" ||
		value.Feature != "networking-vm-external-peer-lab-app" ||
		value.Target != "aarch64-apple-darwin" ||
		value.Source != source ||
		value.RunRoot != runRoot ||
		value.App != filepath.Join(
			runRoot, "cargo-target", "aarch64-apple-darwin",
			"release", "bundle", "macos", "KyClash.app",
		) ||
		value.AppTreeManifest != filepath.Join(runRoot, "app-tree-manifest.json") ||
		value.Provenance != filepath.Join(runRoot, "provenance.json") ||
		!validLowerSHA256(value.AppTreeManifestSHA256) ||
		!validLowerSHA256(value.AppTreeSHA256) ||
		!validLowerSHA256(value.ProvenanceSHA256) ||
		value.SigningIdentity != nil ||
		value.Packages || value.UpdaterArtifacts || value.EmbeddedPrivileged {
		return ErrUnsafeHostCourier
	}
	return nil
}

func validateAppProvenance(
	value appBuildProvenance,
	result appBuildResult,
) error {
	if value.SchemaVersion != 1 ||
		value.Status != "complete" ||
		value.BuildTarget != result.BuildTarget ||
		value.RuntimeExecution ||
		value.RuntimeTarget != result.RuntimeTarget ||
		value.PeerTarget != result.PeerTarget ||
		value.RuntimeMode != result.RuntimeMode ||
		value.Feature != result.Feature ||
		value.Target != result.Target ||
		value.Source != result.Source ||
		value.App != result.App ||
		value.AppTreeManifest != result.AppTreeManifest ||
		value.AppTreeManifestSHA256 != result.AppTreeManifestSHA256 ||
		value.AppTreeSHA256 != result.AppTreeSHA256 ||
		value.ExecutableSHA256 != result.MainExecutable.SHA256 ||
		value.SigningIdentity != nil ||
		value.Packages || value.UpdaterArtifacts || value.EmbeddedPrivileged {
		return ErrUnsafeHostCourier
	}
	return nil
}

func validateAppTreeManifest(
	app string,
	manifest appTreeManifest,
	result appBuildResult,
) error {
	if manifest.SchemaVersion != 1 ||
		manifest.AppName != "KyClash.app" ||
		manifest.Source != result.Source ||
		manifest.TreeSHA256 != result.AppTreeSHA256 ||
		manifest.InfoPlist != result.InfoPlist ||
		manifest.MainExecutable != result.MainExecutable ||
		manifest.InfoPlist.RelativePath != "Contents/Info.plist" ||
		manifest.InfoPlist.BundleIdentifier != "net.kysion.kyclash" ||
		manifest.InfoPlist.BundleExecutable != "clash-verge" ||
		manifest.MainExecutable.RelativePath !=
			"Contents/MacOS/clash-verge" ||
		len(manifest.Entries) == 0 ||
		len(manifest.Entries) > 4096 {
		return ErrUnsafeHostCourier
	}
	encodedEntries, err := json.Marshal(manifest.Entries)
	if err != nil || hashBytes(encodedEntries) != manifest.TreeSHA256 {
		return ErrUnsafeHostCourier
	}
	previous := ""
	for index, entry := range manifest.Entries {
		if entry.RelativePath == "" ||
			filepath.IsAbs(entry.RelativePath) ||
			filepath.Clean(entry.RelativePath) != entry.RelativePath ||
			strings.Contains(entry.RelativePath, `\`) ||
			index > 0 && entry.RelativePath <= previous ||
			(entry.Type != "file" && entry.Type != "directory") ||
			len(entry.Mode) != 4 ||
			!validLowerOctal(entry.Mode) {
			return ErrUnsafeHostCourier
		}
		if index == 0 {
			if entry.RelativePath != "." || entry.Type != "directory" {
				return ErrUnsafeHostCourier
			}
		} else if entry.RelativePath == "." {
			return ErrUnsafeHostCourier
		}
		if entry.Type == "directory" {
			if entry.ByteLength != 0 || entry.SHA256 != nil {
				return ErrUnsafeHostCourier
			}
		} else if entry.SHA256 == nil ||
			entry.ByteLength > 512*1024*1024 ||
			!validLowerSHA256(*entry.SHA256) {
			return ErrUnsafeHostCourier
		}
		previous = entry.RelativePath
	}
	if validateAppTreeOnDisk(app, manifest) != nil {
		return ErrUnsafeHostCourier
	}
	return nil
}

func validateAppTreeOnDisk(app string, manifest appTreeManifest) error {
	actual, err := collectAppTreeOnDisk(app)
	if err != nil || len(actual) != len(manifest.Entries) {
		return ErrUnsafeHostCourier
	}
	for index := range actual {
		if !equalAppTreeEntry(actual[index], manifest.Entries[index]) {
			return ErrUnsafeHostCourier
		}
	}
	return nil
}

func equalAppTreeEntry(left appTreeEntry, right appTreeEntry) bool {
	if left.RelativePath != right.RelativePath ||
		left.Type != right.Type ||
		left.Mode != right.Mode ||
		left.ByteLength != right.ByteLength ||
		(left.SHA256 == nil) != (right.SHA256 == nil) {
		return false
	}
	return left.SHA256 == nil || *left.SHA256 == *right.SHA256
}

func collectAppTreeOnDisk(app string) ([]appTreeEntry, error) {
	info, err := os.Lstat(app)
	if err != nil || !safeBuildDirectory(info, uint32(os.Getuid())) {
		return nil, ErrUnsafeHostCourier
	}
	result := []appTreeEntry{directoryTreeEntry(".", info)}
	var visit func(string, string) error
	visit = func(directory string, prefix string) error {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return ErrUnsafeHostCourier
		}
		sort.Slice(entries, func(left, right int) bool {
			return bytes.Compare(
				[]byte(entries[left].Name()),
				[]byte(entries[right].Name()),
			) < 0
		})
		for _, entry := range entries {
			relative := entry.Name()
			if prefix != "" {
				relative = prefix + "/" + entry.Name()
			}
			absolute := filepath.Join(directory, entry.Name())
			info, err := os.Lstat(absolute)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return ErrUnsafeHostCourier
			}
			if info.IsDir() {
				if !safeBuildDirectory(info, uint32(os.Getuid())) {
					return ErrUnsafeHostCourier
				}
				result = append(result, directoryTreeEntry(relative, info))
				if err := visit(absolute, relative); err != nil {
					return err
				}
				continue
			}
			if !info.Mode().IsRegular() {
				return ErrUnsafeHostCourier
			}
			digest, size, err := hashStableFile(
				absolute, uint32(os.Getuid()), info.Mode().Perm(),
				512*1024*1024,
			)
			if err != nil {
				return err
			}
			result = append(result, appTreeEntry{
				RelativePath: relative,
				Type:         "file", Mode: formatMode(info.Mode().Perm()),
				ByteLength: size, SHA256: &digest,
			})
		}
		return nil
	}
	if err := visit(app, ""); err != nil {
		return nil, err
	}
	return result, nil
}

func directoryTreeEntry(relative string, info os.FileInfo) appTreeEntry {
	return appTreeEntry{
		RelativePath: relative,
		Type:         "directory", Mode: formatMode(info.Mode().Perm()),
		ByteLength: 0, SHA256: nil,
	}
}

func validateBuiltExecutable(
	path string,
	record binaryArtifactRecord,
) error {
	digest, size, err := hashStableFile(
		path, uint32(os.Getuid()), 0o755, 512*1024*1024,
	)
	if err != nil ||
		size != record.ByteLength ||
		digest != record.SHA256 {
		return ErrUnsafeHostCourier
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafeHostCourier
	}
	defer file.Close()
	header := make([]byte, 8)
	if _, err := io.ReadFull(file, header); err != nil ||
		!bytes.Equal(header, []byte{
			0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01,
		}) {
		return ErrUnsafeHostCourier
	}
	return nil
}

func readOwnedRegularFile(
	path string,
	mode os.FileMode,
	maximum int64,
) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		maximum <= 0 {
		return nil, ErrUnsafeHostCourier
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsafeHostCourier
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil ||
		!safeRegularInfo(before, uint32(os.Getuid()), mode) ||
		before.Size() < 0 ||
		before.Size() > maximum {
		return nil, ErrUnsafeHostCourier
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != before.Size() {
		clear(data)
		return nil, ErrUnsafeHostCourier
	}
	after, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil ||
		!os.SameFile(before, after) ||
		!os.SameFile(after, pathInfo) ||
		!before.ModTime().Equal(after.ModTime()) ||
		!after.ModTime().Equal(pathInfo.ModTime()) ||
		!safeRegularInfo(pathInfo, uint32(os.Getuid()), mode) {
		clear(data)
		return nil, ErrUnsafeHostCourier
	}
	return data, nil
}

func hashStableFile(
	path string,
	uid uint32,
	mode os.FileMode,
	maximum uint64,
) (string, uint64, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", 0, ErrUnsafeHostCourier
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil ||
		!safeRegularInfo(before, uid, mode) ||
		before.Size() < 0 ||
		uint64(before.Size()) > maximum {
		return "", 0, ErrUnsafeHostCourier
	}
	hasher := sha256.New()
	read, err := io.Copy(
		hasher,
		io.LimitReader(file, int64(maximum)+1),
	)
	if err != nil || read != before.Size() {
		return "", 0, ErrUnsafeHostCourier
	}
	after, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil ||
		!os.SameFile(before, after) ||
		!os.SameFile(after, pathInfo) ||
		!before.ModTime().Equal(after.ModTime()) ||
		!after.ModTime().Equal(pathInfo.ModTime()) ||
		!safeRegularInfo(pathInfo, uid, mode) {
		return "", 0, ErrUnsafeHostCourier
	}
	return fmtHex(hasher.Sum(nil)), uint64(read), nil
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return ErrUnsafeHostCourier
	}
	return nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return fmtHex(sum[:])
}

func safeBuildDirectory(info os.FileInfo, uid uint32) bool {
	if info == nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Nlink >= 1
}

func formatMode(mode os.FileMode) string {
	const digits = "01234567"
	value := uint32(mode.Perm())
	result := []byte{'0', '0', '0', '0'}
	for index := 3; index >= 0; index-- {
		result[index] = digits[value&7]
		value >>= 3
	}
	return string(result)
}

func validLowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validLowerOctal(value string) bool {
	for _, character := range value {
		if character < '0' || character > '7' {
			return false
		}
	}
	return true
}
