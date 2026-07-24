package externalpeer

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/wgcarrier"
)

func TestChildBootstrapAcceptsOnlyPublicFixedFacts(t *testing.T) {
	fixture := newIdentityFixture(t)
	value := ChildBootstrap{
		SchemaVersion:                SchemaVersion,
		RunID:                        testRunID,
		IssuedAt:                     fixture.now.Unix(),
		ExpiresAt:                    fixture.now.Add(30 * time.Minute).Unix(),
		ClientPlatformUUID:           testClientUUID,
		ClientIPv4:                   testClientIP.String(),
		ClientMAC:                    testClientMAC,
		ClientWireGuardPublicKey:     base64.StdEncoding.EncodeToString(fixture.clientWGPublic),
		ClientDescriptorBase64:       base64.StdEncoding.EncodeToString(fixture.clientArtifacts.Descriptor),
		ClientCSRDERBase64:           base64.StdEncoding.EncodeToString(fixture.clientArtifacts.TLSClientCSRDER),
		ClientOverlayPublicKeyBase64: base64.StdEncoding.EncodeToString(fixture.clientArtifacts.OverlayClientPublicKey),
		PeerPlatformUUID:             testPeerUUID,
		PeerIPv4:                     testPeerIP.String(),
		PeerMAC:                      testPeerMAC,
		SystemSSHHostPublicKeyBase64: base64.StdEncoding.EncodeToString(fixture.systemHostPublic),
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	config, err := DecodeChildBootstrap(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer clearPeerConfigPublicArtifacts(&config)
	if config.PeerIPv4 != testPeerIP ||
		config.Client.ClientIPv4 != testClientIP ||
		config.RunID != testRunID {
		t.Fatalf("unexpected child config: %#v", config)
	}
	withAuthority := append(
		encoded[:len(encoded)-1],
		[]byte(`,"endpoint":"127.0.0.1:1"}`)...,
	)
	if _, err := DecodeChildBootstrap(withAuthority); err == nil {
		t.Fatal("caller-selected endpoint was accepted")
	}
}

func TestRunTicketExpectationIsPinnedOutsidePeerConfig(t *testing.T) {
	config := PeerSupervisorConfig{
		SchemaVersion: SchemaVersion,
		ConsoleUID:    501,
		ConsoleGID:    20,
		PeerChildUID:  502,
		PeerChildGID:  20,
		Client: SupervisorVMConfig{
			Role: "client", VMName: ClientVMName,
			PlatformUUID:       testClientUUID,
			SSHHostFingerprint: "SHA256:client-host-key",
			MAC:                testClientMAC, IPv4: testClientIP.String(),
		},
		Peer: SupervisorVMConfig{
			Role: "peer", VMName: PeerVMName,
			PlatformUUID:       testPeerUUID,
			SSHHostFingerprint: "SHA256:peer-host-key",
			MAC:                testPeerMAC, IPv4: testPeerIP.String(),
		},
	}
	encodedConfig, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePeerSupervisorConfig(encodedConfig); err != nil {
		t.Fatal(err)
	}
	withRecursiveTable := append(
		encodedConfig[:len(encodedConfig)-1],
		[]byte(`,"run_ticket_files":[]}`)...,
	)
	if _, err := DecodePeerSupervisorConfig(withRecursiveTable); err == nil {
		t.Fatal("recursive run-ticket table was accepted in peer config")
	}
	expectation := RunTicketExpectation{
		SchemaVersion: SchemaVersion,
		Files:         make([]ArtifactDigest, 0, len(RunTicketArtifactNames)),
	}
	for index, name := range RunTicketArtifactNames {
		expectation.Files = append(expectation.Files, ArtifactDigest{
			Name: name, Length: uint64(index + 1), SHA256: HashHex([]byte(name)),
		})
	}
	encodedExpectation, err := json.Marshal(expectation)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRunTicketExpectation(encodedExpectation)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Files) != 8 {
		t.Fatalf("unexpected expectation size: %d", len(decoded.Files))
	}
}

func TestListenerParserAndClosedAllowlist(t *testing.T) {
	data := []byte(
		"p123\x00cpeer\x00u502\x00PTCP\x00n192.168.64.22:22001\x00" +
			"p124\x00csshd\x00u0\x00PTCP\x00n*:22\x00" +
			"p125\x00cclient\x00u501\x00PUDP\x00n192.168.64.11:54000->192.168.64.22:22001\x00",
	)
	records, err := parseLsofFields(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 ||
		records[0].BindAddress != "192.168.64.22" ||
		records[0].Port != 22001 ||
		records[1].BindAddress != "0.0.0.0" ||
		records[1].Port != 22 {
		t.Fatalf("unexpected listener records: %#v", records)
	}
	ipv6Records, err := parseLsofFieldsForFamily(
		[]byte("p126\x00csshd\x00u0\x00PTCP\x00n*:22\x00"),
		6,
	)
	if err != nil ||
		len(ipv6Records) != 1 ||
		ipv6Records[0].BindAddress != "::" {
		t.Fatalf("IPv6 wildcard family was lost: %#v %v", ipv6Records, err)
	}
	inventory := ListenerInventory{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().Unix(),
		Listeners: []ListenerRecord{{
			Protocol:         "tcp",
			BindAddress:      "192.168.64.22",
			Port:             22001,
			PID:              123,
			StartIdentity:    "Mon Jul 23 12:00:00 2026",
			UID:              502,
			Command:          "peer",
			ExecutablePath:   PeerChildPath,
			ExecutableSHA256: HashHex([]byte("peer")),
			CodeSignature:    "unsigned",
		}},
	}
	allowlist := []ListenerAllowance{{
		Protocol:         "tcp",
		BindAddress:      "192.168.64.22",
		Port:             22001,
		UID:              502,
		Command:          "peer",
		ExecutablePath:   PeerChildPath,
		ExecutableSHA256: HashHex([]byte("peer")),
		CodeSignature:    "unsigned",
	}}
	if err := ValidateClosedListenerInventory(inventory, allowlist); err != nil {
		t.Fatal(err)
	}
	inventory.Listeners[0].BindAddress = "0.0.0.0"
	if err := ValidateClosedListenerInventory(inventory, allowlist); err == nil {
		t.Fatal("wildcard listener drift was accepted")
	}
}

func TestListenerParserAcceptsOnlyPositivePIDIncludingLaunchd(t *testing.T) {
	launchd, err := parseLsofFieldsForFamily(
		[]byte("p1\x00claunchd\x00u0\x00PTCP\x00n*:22\x00"),
		4,
	)
	if err != nil ||
		len(launchd) != 1 ||
		launchd[0].PID != 1 ||
		launchd[0].Port != 22 {
		t.Fatalf("launchd PID1 listener was not parsed: %#v %v", launchd, err)
	}
	if _, err := parseLsofFieldsForFamily(
		[]byte("p0\x00claunchd\x00u0\x00PTCP\x00n*:22\x00"),
		4,
	); err == nil {
		t.Fatal("PID0 listener was accepted")
	}
}

func TestControlledPacketConnDropsOnlyAfterImpairment(t *testing.T) {
	// The read-loop wrapper is covered without opening a host listener by a
	// deterministic in-memory PacketConn.
	underlay := &scriptedPacketConn{
		packets: [][]byte{[]byte("first"), []byte("second")},
	}
	value := &controlledPacketConn{PacketConn: underlay}
	buffer := make([]byte, 16)
	count, _, err := value.ReadFrom(buffer)
	if err != nil || string(buffer[:count]) != "first" {
		t.Fatalf("unexpected first packet: %q %v", buffer[:count], err)
	}
	value.blocked.Store(true)
	_, _, err = value.ReadFrom(buffer)
	if err == nil || value.dropped.Load() != 1 {
		t.Fatalf("blocked packet was not dropped: count=%d err=%v", value.dropped.Load(), err)
	}
}

func TestQUICProofImpairmentDropsWithoutClosingActiveCarrier(t *testing.T) {
	value := &recordingPacketCarrier{}
	active := newManagedCarrier(profile.QUIC, value)
	packetControl := &controlledPacketConn{
		PacketConn: &scriptedPacketConn{
			packets: [][]byte{[]byte("blocked")},
		},
	}
	peer := &Peer{
		active:          active,
		activeTransport: profile.QUIC,
		carrierEpoch:    1,
		quicPackets:     packetControl,
		proofs: map[profile.Transport]*transportProof{
			profile.QUIC: {},
			profile.WSS:  {},
			profile.TCP:  {},
		},
	}
	token := transportProofToken{transport: profile.QUIC, epoch: 1}
	peer.recordTransportProof(token, true)
	if peer.quicBlocked.Load() {
		t.Fatal("QUIC blocked before both same-carrier proofs")
	}
	peer.recordTransportProof(token, false)
	if !peer.quicBlocked.Load() ||
		!packetControl.blocked.Load() ||
		peer.active != active ||
		value.closeCount != 0 {
		t.Fatalf(
			"QUIC impairment closed instead of dropping: blocked=%v active=%v closes=%d",
			peer.quicBlocked.Load(),
			peer.active == active,
			value.closeCount,
		)
	}
	buffer := make([]byte, 16)
	if _, _, err := packetControl.ReadFrom(buffer); err == nil ||
		packetControl.dropped.Load() != 1 {
		t.Fatal("post-proof QUIC datagram was not dropped")
	}
}

func TestWSSProofImpairmentRefusesOnlyAfterBothSameCarrierProofs(t *testing.T) {
	value := &recordingPacketCarrier{}
	active := newManagedCarrier(profile.WSS, value)
	board := wgcarrier.NewSwitchboard()
	if err := board.Attach(active); err != nil {
		t.Fatal(err)
	}
	peer := &Peer{
		active:          active,
		activeTransport: profile.WSS,
		carrierEpoch:    1,
		board:           board,
		proofs: map[profile.Transport]*transportProof{
			profile.QUIC: {},
			profile.WSS:  {},
			profile.TCP:  {},
		},
	}
	token := transportProofToken{transport: profile.WSS, epoch: 1}
	peer.recordTransportProof(token, false)
	if peer.wssRefused.Load() || value.closeCount != 0 {
		t.Fatal("WSS refused before echo proof")
	}
	peer.recordTransportProof(token, true)
	if !peer.wssRefused.Load() ||
		peer.active != nil ||
		value.closeCount != 1 {
		t.Fatalf(
			"WSS proof did not close exact carrier: refused=%v active=%v closes=%d",
			peer.wssRefused.Load(),
			peer.active != nil,
			value.closeCount,
		)
	}
	status := peer.Status()
	if status.WSSEchoProofs != 1 || status.WSSSSHProofs != 1 {
		t.Fatalf("unexpected WSS proof counters: %#v", status)
	}
}

func TestProofFromClosedCarrierCannotCompleteNextCarrier(t *testing.T) {
	quic := newManagedCarrier(profile.QUIC, &recordingPacketCarrier{})
	wss := newManagedCarrier(profile.WSS, &recordingPacketCarrier{})
	peer := &Peer{
		active:          quic,
		activeTransport: profile.QUIC,
		carrierEpoch:    1,
		proofs: map[profile.Transport]*transportProof{
			profile.QUIC: {},
			profile.WSS:  {},
			profile.TCP:  {},
		},
	}
	old := transportProofToken{transport: profile.QUIC, epoch: 1}
	peer.mu.Lock()
	peer.active = wss
	peer.activeTransport = profile.WSS
	peer.carrierEpoch = 2
	peer.mu.Unlock()
	peer.recordTransportProof(old, true)
	peer.recordTransportProof(old, false)
	status := peer.Status()
	if status.QUICEchoProofs != 0 ||
		status.QUICSSHProofs != 0 ||
		status.WSSEchoProofs != 0 ||
		status.WSSSSHProofs != 0 ||
		peer.quicBlocked.Load() ||
		peer.wssRefused.Load() {
		t.Fatalf("stale carrier proof was misattributed: %#v", status)
	}
}
