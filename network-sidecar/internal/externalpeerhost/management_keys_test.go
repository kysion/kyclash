package externalpeerhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
	"golang.org/x/crypto/ssh"
)

func TestManagementKeyInitCreatesTwoIndependentFixedOpenSSHKeys(
	t *testing.T,
) {
	t.Parallel()
	layout := testLayout(t)
	entropy := append(
		bytes.Repeat([]byte{0x52}, 32),
		bytes.Repeat([]byte{0x53}, 32)...,
	)
	if err := InitializeManagementKeys(
		layout,
		bytes.NewReader(entropy),
	); err != nil {
		t.Fatal(err)
	}
	privateDirectory, err := openSecureDirectory(
		layout.Management,
		uint32(os.Getuid()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer privateDirectory.close()
	publicDirectory, err := openSecureDirectory(
		layout.ManagementPublic,
		uint32(os.Getuid()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer publicDirectory.close()
	if privateDirectory.requireExactNames(managementPrivateNames) != nil ||
		publicDirectory.requireExactNames(managementPublicNames) != nil {
		t.Fatal("management key directories have an open name surface")
	}
	publicValues := make([][]byte, 0, 2)
	for _, value := range []struct {
		private string
		public  string
	}{
		{ClientManagementKeyName, ClientManagementPublicName},
		{PeerManagementKeyName, PeerManagementPublicName},
	} {
		privateBlob, err := privateDirectory.readStableFile(
			value.private,
			maximumManagementKeyBytes,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		publicBlob, err := publicDirectory.readStableFile(
			value.public,
			4096,
			nil,
		)
		if err != nil {
			clear(privateBlob.bytes)
			t.Fatal(err)
		}
		derived, err := rawManagementPublicFromPrivate(privateBlob.bytes)
		clear(privateBlob.bytes)
		if err != nil || !bytes.Equal(derived, publicBlob.bytes) {
			clear(derived)
			clear(publicBlob.bytes)
			t.Fatal("OpenSSH private/public management key mismatch")
		}
		clear(derived)
		publicValues = append(publicValues, publicBlob.bytes)
	}
	defer clearByteSlices(publicValues)
	if bytes.Equal(publicValues[0], publicValues[1]) {
		t.Fatal("client and peer management identities were reused")
	}
	if err := InitializeManagementKeys(
		layout,
		bytes.NewReader(append(
			bytes.Repeat([]byte{0x54}, 32),
			bytes.Repeat([]byte{0x55}, 32)...,
		)),
	); err == nil {
		t.Fatal("management-key-init replaced existing keys")
	}
}

func TestManagementHostKeyPinRequiresReviewedGuestWitnessesAndNoTOFU(
	t *testing.T,
) {
	t.Parallel()
	t.Run("success and create-only", func(t *testing.T) {
		layout := testLayout(t)
		fixture := newHostTransactionFixture(t)
		prepareManagementPinFixture(t, layout, fixture)
		if err := PinReviewedManagementHostKeys(layout); err != nil {
			t.Fatal(err)
		}
		store, err := openManagementStore(layout, fixture.input.Config)
		if err != nil {
			t.Fatal(err)
		}
		store.close()
		if err := PinReviewedManagementHostKeys(layout); err == nil {
			t.Fatal("host-key pin reused existing known_hosts files")
		}
	})
	t.Run("missing explicit review", func(t *testing.T) {
		layout := testLayout(t)
		fixture := newHostTransactionFixture(t)
		prepareManagementPinFixture(t, layout, fixture)
		if err := os.Remove(
			filepath.Join(
				layout.ManagementReview,
				PeerHostFingerprintName,
			),
		); err != nil {
			t.Fatal(err)
		}
		if err := PinReviewedManagementHostKeys(layout); err == nil {
			t.Fatal("pinning fell back to first-use host-key acceptance")
		}
	})
	t.Run("tampered witness", func(t *testing.T) {
		layout := testLayout(t)
		fixture := newHostTransactionFixture(t)
		prepareManagementPinFixture(t, layout, fixture)
		path := filepath.Join(
			layout.ManagementReview,
			ClientSSHBootstrapWitnessName,
		)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data[0] ^= 1
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		clear(data)
		if err := PinReviewedManagementHostKeys(layout); err == nil {
			t.Fatal("tampered guest SSH witness was accepted")
		}
	})
	t.Run("symlinked host public key", func(t *testing.T) {
		layout := testLayout(t)
		fixture := newHostTransactionFixture(t)
		prepareManagementPinFixture(t, layout, fixture)
		path := filepath.Join(
			layout.ManagementReview,
			PeerHostPublicReviewName,
		)
		target := filepath.Join(t.TempDir(), "host-public.bin")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatal(err)
		}
		clear(data)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := PinReviewedManagementHostKeys(layout); err == nil {
			t.Fatal("symlinked reviewed host key was accepted")
		}
	})
}

func prepareManagementPinFixture(
	t *testing.T,
	layout Layout,
	fixture hostTransactionFixture,
) {
	t.Helper()
	if err := InitializeManagementKeys(
		layout,
		bytes.NewReader(append(
			bytes.Repeat([]byte{0x61}, 32),
			bytes.Repeat([]byte{0x62}, 32)...,
		)),
	); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.Control, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(layout.Workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(layout.Control, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSecureTestFile(
		t,
		filepath.Join(layout.Control, PeerConfigName),
		fixture.configRaw,
	)
	writeSecureTestFile(
		t,
		filepath.Join(layout.Control, TicketExpectationName),
		fixture.ticketRaw,
	)
	if err := os.Mkdir(layout.ManagementReview, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, value := range []struct {
		role              string
		runtimeTarget     string
		hostPublic        []byte
		hostPublicName    string
		fingerprintName   string
		witnessName       string
		managementPubName string
	}{
		{
			"client", vmexternalpeerlab.RuntimeTarget,
			fixture.clientManagementPublic,
			ClientHostPublicReviewName,
			ClientHostFingerprintName,
			ClientSSHBootstrapWitnessName,
			ClientManagementPublicName,
		},
		{
			"peer", vmexternalpeerlab.PeerRuntimeTarget,
			fixture.peerManagementPublic,
			PeerHostPublicReviewName,
			PeerHostFingerprintName,
			PeerSSHBootstrapWitnessName,
			PeerManagementPublicName,
		},
	} {
		managementPublic, err := os.ReadFile(
			filepath.Join(layout.ManagementPublic, value.managementPubName),
		)
		if err != nil {
			t.Fatal(err)
		}
		managementKey, err := parseCanonicalRawED25519(managementPublic)
		if err != nil {
			clear(managementPublic)
			t.Fatal(err)
		}
		hostKey, err := parseCanonicalRawED25519(value.hostPublic)
		if err != nil {
			clear(managementPublic)
			t.Fatal(err)
		}
		allowed := []string{managementConsoleUser}
		restricted := false
		regenerated := false
		if value.role == "peer" {
			allowed = append(allowed, "kyclashlabssh")
			restricted = true
			regenerated = true
		}
		authorized := ssh.MarshalAuthorizedKey(managementKey)
		recovery := sha256.Sum256([]byte("reviewed-recovery-" + value.role))
		witness := managementBootstrapWitness{
			SchemaVersion: 1,
			Role:          value.role, RuntimeTarget: value.runtimeTarget,
			ConsoleUser:         managementConsoleUser,
			ConsoleUID:          fixture.input.Config.ConsoleUID,
			ConsoleGID:          fixture.input.Config.ConsoleGID,
			RemoteLoginVerified: true, PublicKeyOnlyVerified: true,
			ForwardingDisabled: true, RootLoginDisabled: true,
			AllowedUsers:        allowed,
			ManagementKeySHA256: hashHex(managementPublic),
			ManagementKeyFingerprint: ssh.FingerprintSHA256(
				managementKey,
			),
			AuthorizedKeysSHA256:      hashHex(authorized),
			HostKeySHA256:             hashHex(value.hostPublic),
			HostKeyFingerprint:        ssh.FingerprintSHA256(hostKey),
			RestrictedAccountVerified: restricted,
			PeerHostKeysRegenerated:   regenerated,
			RecoveryRecordSHA256:      fmtHex(recovery[:]),
			CompletedAt:               fixture.now.Unix(),
		}
		clear(managementPublic)
		clear(authorized)
		witnessBytes, err := json.Marshal(witness)
		if err != nil {
			t.Fatal(err)
		}
		witnessBytes = append(witnessBytes, '\n')
		writeSecureTestFile(
			t,
			filepath.Join(layout.ManagementReview, value.hostPublicName),
			value.hostPublic,
		)
		writeSecureTestFile(
			t,
			filepath.Join(layout.ManagementReview, value.fingerprintName),
			[]byte(ssh.FingerprintSHA256(hostKey)+"\n"),
		)
		writeSecureTestFile(
			t,
			filepath.Join(layout.ManagementReview, value.witnessName),
			witnessBytes,
		)
		clear(witnessBytes)
	}
}

func writeSecureTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}
