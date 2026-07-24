package externalpeer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStagedFileBindsDeviceInodeSizeAndHash(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "peer-config.json")
	original := []byte("fixed-staged-bytes")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	expected := stagedFileFromPath(t, path, 0o600)
	if err := validateStagedFile(expected); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), original...)
	changed[0] ^= 1
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateStagedFile(expected); err == nil {
		t.Fatal("same-inode content replacement was accepted")
	}
	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(replacement, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := validateStagedFile(expected); err == nil {
		t.Fatal("same-byte inode replacement was accepted")
	}
}

func TestPeerStagingManifestRequiresListenerBaselineAndStableIdentity(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	staged := func(path string, mode uint32, salt string) StagedFile {
		return StagedFile{
			Path:   path,
			SHA256: HashHex([]byte(salt)),
			UID:    0,
			Mode:   mode,
			Device: 1,
			Inode:  2,
			Size:   3,
		}
	}
	manifest := PeerStagingManifest{
		SchemaVersion:        SchemaVersion,
		PeerSupervisor:       staged(PeerSupervisorPath, 0o755, "supervisor"),
		PeerChild:            staged(PeerChildPath, 0o755, "child"),
		PeerConfig:           staged(PeerFixedConfigPath, 0o600, "config"),
		RunTicketExpectation: staged(PeerRunTicketExpectationPath, 0o600, "ticket"),
		PeerListenerBaseline: staged(PeerListenerBaselinePath, 0o600, "baseline"),
		ListenerAuditor:      staged(ListenerAuditorPath, 0o755, "auditor"),
		ForcedCommandHelper:  staged(ForcedCommandHelperPath, 0o755, "forced"),
		CourierPublicKeyBase64: base64.StdEncoding.EncodeToString(
			publicKey,
		),
		CourierPublicKeyFingerprint: HashHex(publicKey),
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePeerStagingManifest(encoded); err != nil {
		t.Fatal(err)
	}
	withoutBaseline := manifest
	withoutBaseline.PeerListenerBaseline = StagedFile{}
	encoded, _ = json.Marshal(withoutBaseline)
	if _, err := DecodePeerStagingManifest(encoded); err == nil {
		t.Fatal("manifest without pinned listener baseline was accepted")
	}
	withoutIdentity := manifest
	withoutIdentity.PeerChild.Inode = 0
	encoded, _ = json.Marshal(withoutIdentity)
	if _, err := DecodePeerStagingManifest(encoded); err == nil {
		t.Fatal("manifest without staged inode was accepted")
	}
}

func stagedFileFromPath(
	t *testing.T,
	path string,
	mode uint32,
) StagedFile {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("missing stat identity")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return StagedFile{
		Path:   path,
		SHA256: HashHex(data),
		UID:    stat.Uid,
		Mode:   mode,
		Device: uint64(stat.Dev),
		Inode:  uint64(stat.Ino),
		Size:   uint64(info.Size()),
	}
}
