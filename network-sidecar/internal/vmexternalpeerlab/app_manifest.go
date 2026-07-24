package vmexternalpeerlab

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
)

const (
	AppManifestSchemaVersion = 2
	MaximumAppManifestSize   = 4096
)

var ErrInvalidAppManifest = errors.New("invalid external-peer App manifest")

// AppManifestV2 is the root-pinned identity consumed by the client
// supervisor. It deliberately identifies an unsigned App by exact filesystem
// identity and bytes rather than by a signing claim.
type AppManifestV2 struct {
	SchemaVersion                uint8  `json:"schema_version"`
	RuntimeTarget                string `json:"runtime_target"`
	ExecutablePath               string `json:"executable_path"`
	ExpectedAuditUID             uint32 `json:"expected_audit_uid"`
	ExecutableUID                uint32 `json:"executable_uid"`
	ExecutableMode               uint32 `json:"executable_mode"`
	ExecutableDevice             uint64 `json:"executable_device"`
	ExecutableInode              uint64 `json:"executable_inode"`
	ExecutableSize               uint64 `json:"executable_size"`
	ExecutableSHA256             string `json:"executable_sha256"`
	AppTreeSHA256                string `json:"app_tree_sha256"`
	AppTreeManifestSHA256        string `json:"app_tree_manifest_sha256"`
	Architecture                 string `json:"architecture"`
	RunTicketExpectationSHA256   string `json:"run_ticket_expectation_sha256"`
	PeerConfigSHA256             string `json:"peer_config_sha256"`
	CourierPublicKeySHA256       string `json:"courier_public_key_sha256"`
	ClientListenerBaselineSHA256 string `json:"client_listener_baseline_sha256"`
	HarnessExecutableDevice      uint64 `json:"harness_executable_device"`
	HarnessExecutableInode       uint64 `json:"harness_executable_inode"`
	HarnessExecutableSize        uint64 `json:"harness_executable_size"`
	HarnessExecutableSHA256      string `json:"harness_executable_sha256"`
}

func DecodeAppManifestV2(reader io.Reader) (AppManifestV2, error) {
	if reader == nil {
		return AppManifestV2{}, ErrInvalidAppManifest
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaximumAppManifestSize+1))
	if err != nil || len(raw) == 0 || len(raw) > MaximumAppManifestSize {
		return AppManifestV2{}, ErrInvalidAppManifest
	}
	defer clear(raw)
	if rejectDuplicateAppManifestKeys(raw) != nil {
		return AppManifestV2{}, ErrInvalidAppManifest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest AppManifestV2
	if decoder.Decode(&manifest) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		manifest.Validate() != nil {
		return AppManifestV2{}, ErrInvalidAppManifest
	}
	return manifest, nil
}

func EncodeAppManifestV2(manifest AppManifestV2) ([]byte, error) {
	if manifest.Validate() != nil {
		return nil, ErrInvalidAppManifest
	}
	encoded, err := json.Marshal(manifest)
	if err != nil || len(encoded)+1 > MaximumAppManifestSize {
		return nil, ErrInvalidAppManifest
	}
	return append(encoded, '\n'), nil
}

func (manifest AppManifestV2) Validate() error {
	if manifest.SchemaVersion != AppManifestSchemaVersion ||
		manifest.RuntimeTarget != RuntimeTarget ||
		manifest.ExpectedAuditUID == 0 ||
		manifest.ExecutableUID != 0 ||
		manifest.ExecutableMode != 0o755 ||
		manifest.ExecutableDevice == 0 ||
		manifest.ExecutableInode == 0 ||
		manifest.ExecutableSize < 32 ||
		manifest.HarnessExecutableDevice == 0 ||
		manifest.HarnessExecutableInode == 0 ||
		manifest.HarnessExecutableSize < 32 ||
		manifest.Architecture != "arm64" {
		return ErrInvalidAppManifest
	}
	if manifest.ExecutablePath != AppExecutablePath ||
		!filepath.IsAbs(manifest.ExecutablePath) ||
		filepath.Clean(manifest.ExecutablePath) != manifest.ExecutablePath {
		return ErrInvalidAppManifest
	}
	for _, digest := range []string{
		manifest.ExecutableSHA256,
		manifest.AppTreeSHA256,
		manifest.AppTreeManifestSHA256,
		manifest.RunTicketExpectationSHA256,
		manifest.PeerConfigSHA256,
		manifest.CourierPublicKeySHA256,
		manifest.ClientListenerBaselineSHA256,
		manifest.HarnessExecutableSHA256,
	} {
		if !validLowerSHA256(digest) {
			return ErrInvalidAppManifest
		}
	}
	return nil
}

func rejectDuplicateAppManifestKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ErrInvalidAppManifest
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return ErrInvalidAppManifest
		}
		if _, exists := seen[key]; exists {
			return ErrInvalidAppManifest
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return ErrInvalidAppManifest
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return ErrInvalidAppManifest
	}
	if token, err = decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return ErrInvalidAppManifest
	}
	return nil
}

func validLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
