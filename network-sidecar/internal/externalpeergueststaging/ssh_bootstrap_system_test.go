package externalpeergueststaging

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHBootstrapPolicyIsRoleSeparatedAndKeyOnly(t *testing.T) {
	client := expectedSSHDPolicy(ClientRole, "supen")
	peer := expectedSSHDPolicy(PeerRole, "supen")
	for _, policy := range []string{client, peer} {
		for _, required := range []string{
			"AuthenticationMethods publickey\n",
			"PubkeyAuthentication yes\n",
			"PasswordAuthentication no\n",
			"KbdInteractiveAuthentication no\n",
			"PermitRootLogin no\n",
			"DisableForwarding yes\n",
			"AllowAgentForwarding no\n",
			"AllowTcpForwarding no\n",
			"AllowStreamLocalForwarding no\n",
			"X11Forwarding no\n",
			"GatewayPorts no\n",
			"PermitTunnel no\n",
		} {
			if !strings.Contains(policy, required) {
				t.Fatalf("policy omitted %q", required)
			}
		}
	}
	if !strings.Contains(client, "AllowUsers supen\n") ||
		strings.Contains(client, restrictedSSHAccount) {
		t.Fatal("client policy did not isolate the console account")
	}
	if !strings.Contains(
		peer,
		"AllowUsers supen "+restrictedSSHAccount+"\n",
	) {
		t.Fatal("peer policy did not isolate the two exact accounts")
	}
}

func TestSSHDMainIncludeAndEarlierFragmentBoundariesAreStrict(t *testing.T) {
	valid := []byte(
		"# global\n" +
			"UseDNS no\n" +
			"Include /etc/ssh/sshd_config.d/*\n" +
			"PasswordAuthentication yes\n" +
			"Match User nobody\n" +
			"  X11Forwarding yes\n",
	)
	if err := validateSSHDMainConfig(valid); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{
		"controlled-before-include": []byte(
			"PasswordAuthentication yes\n" +
				"Include /etc/ssh/sshd_config.d/*\n",
		),
		"include-after-match": []byte(
			"Match User nobody\n" +
				"Include /etc/ssh/sshd_config.d/*\n",
		),
		"duplicate-include": []byte(
			"Include /etc/ssh/sshd_config.d/*\n" +
				"Include /etc/ssh/sshd_config.d/*\n",
		),
		"other-include": []byte("Include /tmp/*.conf\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateSSHDMainConfig(value); err == nil {
				t.Fatal("unsafe sshd main configuration was accepted")
			}
		})
	}
	if err := validateEarlierSSHDFragment(
		[]byte("UseDNS no\nLogLevel INFO\n"),
	); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range [][]byte{
		[]byte("PasswordAuthentication yes\n"),
		[]byte("Match User supen\n"),
		[]byte("Include /tmp/*.conf\n"),
	} {
		if err := validateEarlierSSHDFragment(fragment); err == nil {
			t.Fatal("earlier fragment could shadow the KyClash policy")
		}
	}
}

func TestEffectiveSSHDContextRequiresEveryRestrictedDirective(t *testing.T) {
	fields := map[string]string{
		"authenticationmethods":           "publickey",
		"pubkeyauthentication":            "yes",
		"passwordauthentication":          "no",
		"kbdinteractiveauthentication":    "no",
		"challengeresponseauthentication": "no",
		"permitrootlogin":                 "no",
		"disableforwarding":               "yes",
		"allowagentforwarding":            "no",
		"allowtcpforwarding":              "no",
		"allowstreamlocalforwarding":      "no",
		"x11forwarding":                   "no",
		"gatewayports":                    "no",
		"permittunnel":                    "no",
		"allowusers":                      "supen " + restrictedSSHAccount,
	}
	if err := validateEffectiveSSHDFields(
		fields,
		"supen "+restrictedSSHAccount,
	); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"passwordauthentication",
		"allowtcpforwarding",
		"allowusers",
	} {
		changed := make(map[string]string, len(fields))
		for key, value := range fields {
			changed[key] = value
		}
		changed[name] = "yes"
		if err := validateEffectiveSSHDFields(
			changed,
			"supen "+restrictedSSHAccount,
		); err == nil {
			t.Fatalf("effective sshd context accepted changed %s", name)
		}
	}
}

func TestPartialRestrictedAccountValidationAllowsOnlyPlannedFields(t *testing.T) {
	partial := map[string][]string{
		"RecordName":       {restrictedSSHAccount},
		"UniqueID":         {"502"},
		"PrimaryGroupID":   {"20"},
		"NFSHomeDirectory": {"/Users/" + restrictedSSHAccount},
	}
	if err := validatePartialRestrictedAccountFields(partial); err != nil {
		t.Fatal(err)
	}
	wrongUID := cloneDSCLFields(partial)
	wrongUID["UniqueID"] = []string{"503"}
	if err := validatePartialRestrictedAccountFields(wrongUID); err == nil {
		t.Fatal("partial restricted account accepted a foreign UID")
	}
	enabled := cloneDSCLFields(partial)
	enabled["AuthenticationAuthority"] = []string{";ShadowHash;"}
	if err := validatePartialRestrictedAccountFields(enabled); err == nil {
		t.Fatal("partial restricted account accepted enabled authentication")
	}
	disabled := cloneDSCLFields(partial)
	disabled["AuthenticationAuthority"] = []string{";DisabledUser;"}
	if err := validatePartialRestrictedAccountFields(disabled); err != nil {
		t.Fatal(err)
	}
}

func cloneDSCLFields(
	value map[string][]string,
) map[string][]string {
	result := make(map[string][]string, len(value))
	for key, fields := range value {
		result[key] = append([]string(nil), fields...)
	}
	return result
}

func TestSSHBootstrapRequestRequiresCanonicalRoleSpecificRawKey(t *testing.T) {
	private := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x65}, ed25519.SeedSize),
	)
	key, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	raw := key.Marshal()
	request := SSHBootstrapRequest{
		Role:                     ClientRole,
		RuntimeTarget:            "kyclash-macos-lab-work",
		ConsoleUID:               501,
		ConsoleGID:               20,
		ManagementPublicKey:      raw,
		ManagementKeySHA256:      hashHex(raw),
		ManagementKeyFingerprint: ssh.FingerprintSHA256(key),
	}
	if err := validateSSHBootstrapRequest(request); err != nil {
		t.Fatal(err)
	}
	authorized := request
	authorized.ManagementPublicKey = ssh.MarshalAuthorizedKey(key)
	authorized.ManagementKeySHA256 = hashHex(authorized.ManagementPublicKey)
	if err := validateSSHBootstrapRequest(authorized); err == nil {
		t.Fatal("authorized_keys text was accepted as the canonical raw key")
	}
	wrongRole := request
	wrongRole.Role = PeerRole
	if err := validateSSHBootstrapRequest(wrongRole); err == nil {
		t.Fatal("client runtime target was accepted for the peer role")
	}
}

func TestBootstrapRecoveryRecordIsStrictAndRoundTrips(t *testing.T) {
	private := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x44}, ed25519.SeedSize),
	)
	key, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	public := key.Marshal()
	record := bootstrapRecoveryRecord{
		SchemaVersion: 1,
		Role:          ClientRole,
		RuntimeTarget: "kyclash-macos-lab-work",
		Console: bootstrapAccount{
			Name:  "supen",
			UID:   501,
			GID:   20,
			Home:  "/Users/supen",
			Shell: "/bin/zsh",
		},
		ManagementKeySHA256:        hashHex(public),
		ManagementKeyFingerprint:   ssh.FingerprintSHA256(key),
		ManagementPublicKey:        public,
		ConsoleSSHDirectoryExisted: true,
		ConsoleAuthorizedKeys: recoveryFile{
			Path:             "/Users/supen/.ssh/authorized_keys",
			Existed:          true,
			Device:           1,
			Inode:            2,
			UID:              501,
			GID:              20,
			Mode:             0o600,
			Links:            1,
			Size:             12,
			ModifiedUnixNano: 123,
			SHA256:           strings.Repeat("b", 64),
			BackupName:       "console-authorized-keys",
		},
		SSHDPolicyWasAbsent: true,
		CreatedAt:           time.Now().UTC().Unix(),
	}
	encoded, err := encodeBootstrapRecoveryRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBootstrapRecoveryRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Console != record.Console ||
		decoded.ConsoleAuthorizedKeys != record.ConsoleAuthorizedKeys {
		t.Fatal("recovery record lost an exact original identity")
	}
	unknown := bytes.Replace(
		encoded,
		[]byte(`"schema_version":1`),
		[]byte(`"schema_version":1,"unknown":true`),
		1,
	)
	if _, err := decodeBootstrapRecoveryRecord(unknown); err == nil {
		t.Fatal("unknown recovery field was accepted")
	}
}

func TestBootstrapParsersRejectAmbiguity(t *testing.T) {
	dscl := []byte(
		"NFSHomeDirectory: /Users/supen\n" +
			"PrimaryGroupID: 20\n" +
			"UniqueID: 501\n" +
			"UserShell: /bin/zsh\n",
	)
	fields, err := parseDSCLFields(dscl)
	if err != nil ||
		singleField(fields, "NFSHomeDirectory") != "/Users/supen" {
		t.Fatal("valid dscl output was not decoded")
	}
	if _, err := parseDSCLFields(
		append(dscl, []byte("UniqueID: 502\n")...),
	); err == nil {
		t.Fatal("duplicate dscl field was accepted")
	}
	sshd := []byte(
		"passwordauthentication no\n" +
			"permitrootlogin no\n" +
			"allowusers supen\n",
	)
	decoded, err := parseSSHDFields(sshd)
	if err != nil || decoded["allowusers"] != "supen" {
		t.Fatal("valid sshd -T output was not decoded")
	}
	if _, err := parseSSHDFields(
		append(sshd, []byte("allowusers foreign\n")...),
	); err == nil {
		t.Fatal("duplicate effective sshd directive was accepted")
	}
}

func TestGeneratedHostKeyWitnessPinsEveryExactReplacement(t *testing.T) {
	record := generatedHostKeysRecord{
		SchemaVersion: 1,
		Files:         make([]recoveryFile, 0, len(peerSSHHostKeyPaths)),
	}
	for index, path := range peerSSHHostKeyPaths {
		record.Files = append(record.Files, recoveryFile{
			Path:             path,
			Existed:          true,
			Device:           1,
			Inode:            uint64(index + 10),
			UID:              0,
			GID:              0,
			Mode:             uint32(expectedSSHHostKeyMode(path)),
			Links:            1,
			Size:             uint64(index + 32),
			ModifiedUnixNano: int64(index + 100),
			SHA256:           strings.Repeat(string(rune('a'+index)), 64),
			BackupName:       "generated-" + string(rune('a'+index)),
		})
	}
	encoded, err := encodeGeneratedHostKeys(record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeGeneratedHostKeys(encoded)
	if err != nil || len(decoded.Files) != len(peerSSHHostKeyPaths) {
		t.Fatal("strict generated-host-key witness did not round trip")
	}
	tampered := record
	tampered.Files = append([]recoveryFile(nil), record.Files...)
	tampered.Files[0].Path = peerSSHHostKeyPaths[1]
	if _, err := encodeGeneratedHostKeys(tampered); err == nil {
		t.Fatal("generated-host-key witness accepted a changed fixed path")
	}
}
