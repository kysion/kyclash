package externalpeer

import (
	"encoding/json"
	"testing"
	"time"
)

func testPeerVMConfig() SupervisorVMConfig {
	return SupervisorVMConfig{
		Role:               "peer",
		VMName:             PeerVMName,
		PlatformUUID:       testPeerUUID,
		SSHHostFingerprint: "SHA256:peer-host-key",
		MAC:                testPeerMAC,
		IPv4:               testPeerIP.String(),
	}
}

func testBaselineAllowance() ListenerAllowance {
	return ListenerAllowance{
		Protocol:         "tcp",
		BindAddress:      "127.0.0.1",
		Port:             22,
		UID:              0,
		Command:          "sshd",
		ExecutablePath:   "/usr/sbin/sshd",
		ExecutableSHA256: HashHex([]byte("sshd")),
		CodeSignature:    "apple-anchor;identifier=com.openssh.sshd;team=APPLE;authority=Apple",
		LaunchdLabel:     "com.openssh.sshd",
	}
}

func TestNewListenerBaselineKeepsReviewedWildcardAndStripsProcessIdentity(t *testing.T) {
	allowance := testBaselineAllowance()
	allowance.BindAddress = "0.0.0.0"
	record := listenerRecordFromAllowance(allowance)
	record.PID = 987
	record.StartIdentity = "1710000000:123456"
	inventory := ListenerInventory{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().Unix(),
		Listeners:     []ListenerRecord{record},
	}
	baseline, err := NewListenerBaseline(testPeerVMConfig(), inventory)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Listeners) != 1 ||
		baseline.Listeners[0].BindAddress != "0.0.0.0" {
		t.Fatalf("reviewed wildcard listener was lost: %#v", baseline)
	}
	encoded, err := EncodeListenerBaseline(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if stringContains(string(encoded), `"pid"`) ||
		stringContains(string(encoded), `"start_identity"`) {
		t.Fatal("volatile process identity leaked into baseline allowance")
	}
	decoded, err := DecodeListenerBaseline(encoded)
	if err != nil {
		t.Fatal(err)
	}
	record.PID++
	record.StartIdentity = "1710000100:654321"
	if err := ValidateBaselineListenerInventory(
		ListenerInventory{
			SchemaVersion: SchemaVersion,
			CollectedAt:   time.Now().Unix(),
			Listeners:     []ListenerRecord{record},
		},
		decoded,
	); err != nil {
		t.Fatal("reviewed wildcard did not survive a process restart:", err)
	}
	record.Port++
	if err := ValidateBaselineListenerInventory(
		ListenerInventory{
			SchemaVersion: SchemaVersion,
			CollectedAt:   time.Now().Unix(),
			Listeners:     []ListenerRecord{record},
		},
		decoded,
	); err == nil {
		t.Fatal("wildcard listener port drift was accepted")
	}
}

func TestListenerBaselineExplicitlyPinsReviewedAppleLaunchdPID1(t *testing.T) {
	allowance := ListenerAllowance{
		Protocol:         "tcp",
		BindAddress:      "0.0.0.0",
		Port:             22,
		UID:              0,
		Command:          "launchd",
		ExecutablePath:   "/sbin/launchd",
		ExecutableSHA256: HashHex([]byte("launchd")),
		CodeSignature:    "apple-anchor;identifier=com.apple.xpc.launchd;team=APPLE;authority=Apple",
		LaunchdLabel:     "com.apple.launchd",
		LaunchdPID1:      true,
	}
	record := listenerRecordFromAllowance(allowance)
	record.PID = 1
	inventory := ListenerInventory{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().Unix(),
		Listeners:     []ListenerRecord{record},
	}
	baseline, err := NewListenerBaseline(testPeerVMConfig(), inventory)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Listeners) != 1 ||
		!baseline.Listeners[0].LaunchdPID1 {
		t.Fatalf("launchd PID1 review marker was lost: %#v", baseline)
	}
	encoded, err := EncodeListenerBaseline(baseline)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeListenerBaseline(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBaselineListenerInventory(inventory, decoded); err != nil {
		t.Fatal(err)
	}
	inventory.Listeners[0].PID = 2
	if err := ValidateBaselineListenerInventory(inventory, decoded); err == nil {
		t.Fatal("non-PID1 process was accepted for reviewed launchd socket")
	}
	inventory.Listeners[0].PID = 1
	inventory.Listeners[0].CodeSignature = "unsigned"
	if err := ValidateBaselineListenerInventory(inventory, decoded); err == nil {
		t.Fatal("unsigned PID1 listener was accepted")
	}
}

func TestRuntimeChildIdentityStillRejectsPID1(t *testing.T) {
	child := testChildIdentity(testRunID)
	child.PID = 1
	child.SessionID = 1
	if err := child.Validate(testRunID); err == nil {
		t.Fatal("runtime child PID1 was accepted")
	}
}

func stringContains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}

func listenerRecordFromAllowance(value ListenerAllowance) ListenerRecord {
	return ListenerRecord{
		Protocol:         value.Protocol,
		BindAddress:      value.BindAddress,
		Port:             value.Port,
		PID:              101,
		StartIdentity:    "Mon Jul 23 12:00:00 2026",
		UID:              value.UID,
		Command:          value.Command,
		ExecutablePath:   value.ExecutablePath,
		ExecutableSHA256: value.ExecutableSHA256,
		CodeSignature:    value.CodeSignature,
		LaunchdLabel:     value.LaunchdLabel,
	}
}

func TestListenerBaselineStrictCodecAndVMFacts(t *testing.T) {
	baseline := ListenerBaseline{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().Unix(),
		VM:            testPeerVMConfig(),
		Listeners:     []ListenerAllowance{testBaselineAllowance()},
	}
	encoded, err := EncodeListenerBaseline(baseline)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeListenerBaseline(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.VM != baseline.VM ||
		len(decoded.Listeners) != 1 {
		t.Fatalf("unexpected decoded baseline: %#v", decoded)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = true
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeListenerBaseline(unknown); err == nil {
		t.Fatal("unknown baseline field was accepted")
	}
	duplicate := append(
		[]byte(`{"schema_version":1,`),
		encoded[1:]...,
	)
	if _, err := DecodeListenerBaseline(duplicate); err == nil {
		t.Fatal("duplicate baseline field was accepted")
	}
	wrong := testPeerVMConfig()
	wrong.PlatformUUID = testClientUUID
	if err := decoded.ValidateForVM(wrong); err == nil {
		t.Fatal("baseline was accepted for another VM")
	}
}

func TestBaselineInventoryRejectsMissingExtraAndChangedListeners(t *testing.T) {
	allowance := testBaselineAllowance()
	baseline := ListenerBaseline{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().Unix(),
		VM:            testPeerVMConfig(),
		Listeners:     []ListenerAllowance{allowance},
	}
	inventory := ListenerInventory{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().Unix(),
		Listeners: []ListenerRecord{
			listenerRecordFromAllowance(allowance),
		},
	}
	if err := ValidateBaselineListenerInventory(inventory, baseline); err != nil {
		t.Fatal(err)
	}
	inventory.Listeners[0].PID = 202
	inventory.Listeners[0].StartIdentity = "Mon Jul 23 12:30:00 2026"
	if err := ValidateBaselineListenerInventory(inventory, baseline); err != nil {
		t.Fatal("restarted baseline process identity must not change the pinned listener allowance:", err)
	}
	inventory.Listeners[0].ExecutableSHA256 = HashHex([]byte("changed"))
	if err := ValidateBaselineListenerInventory(inventory, baseline); err == nil {
		t.Fatal("changed listener executable was accepted")
	}
	inventory.Listeners = nil
	if err := ValidateBaselineListenerInventory(inventory, baseline); err == nil {
		t.Fatal("missing baseline listener was accepted")
	}
}

func TestPeerRuntimeListenerInventoryAllowsOnlyBoundChildPorts(t *testing.T) {
	fixture := newIdentityFixture(t)
	allowance := testBaselineAllowance()
	baseline := ListenerBaseline{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().Unix(),
		VM:            testPeerVMConfig(),
		Listeners:     []ListenerAllowance{allowance},
	}
	child := ChildIdentity{
		PID:           404,
		StartIdentity: "Mon Jul 23 12:00:01 2026",
		Path:          PeerChildPath,
		Device:        1,
		Inode:         2,
		SHA256:        HashHex([]byte("peer-child")),
		UID:           502,
		SessionID:     404,
		RunID:         testRunID,
	}
	inventory := ListenerInventory{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().Unix(),
		Listeners: []ListenerRecord{
			listenerRecordFromAllowance(allowance),
			runtimeListenerRecord(child, "udp", 22001),
			runtimeListenerRecord(child, "tcp", 22002),
			runtimeListenerRecord(child, "tcp", 22003),
		},
	}
	if err := ValidatePeerRuntimeListenerInventory(
		inventory,
		baseline,
		fixture.peerDescriptor,
		child,
	); err != nil {
		t.Fatal(err)
	}
	inventory.Listeners[3].Port = 22004
	if err := ValidatePeerRuntimeListenerInventory(
		inventory,
		baseline,
		fixture.peerDescriptor,
		child,
	); err == nil {
		t.Fatal("unpublished child listener was accepted")
	}
	inventory.Listeners[3] = runtimeListenerRecord(child, "tcp", 22003)
	inventory.Listeners[3].CodeSignature = "identifier=foreign"
	if err := ValidatePeerRuntimeListenerInventory(
		inventory,
		baseline,
		fixture.peerDescriptor,
		child,
	); err == nil {
		t.Fatal("signed or substituted child listener was accepted")
	}
}

func runtimeListenerRecord(
	child ChildIdentity,
	protocol string,
	port uint16,
) ListenerRecord {
	return ListenerRecord{
		Protocol:         protocol,
		BindAddress:      testPeerIP.String(),
		Port:             port,
		PID:              child.PID,
		StartIdentity:    child.StartIdentity,
		UID:              child.UID,
		Command:          "kyclash-vm-ex",
		ExecutablePath:   child.Path,
		ExecutableSHA256: child.SHA256,
		CodeSignature:    "unsigned",
	}
}
