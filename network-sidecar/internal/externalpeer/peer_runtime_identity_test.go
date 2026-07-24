package externalpeer

import "testing"

func testPeerRuntimeConfig() PeerSupervisorConfig {
	return PeerSupervisorConfig{
		SchemaVersion: SchemaVersion,
		ConsoleUID:    501,
		ConsoleGID:    20,
		PeerChildUID:  502,
		PeerChildGID:  20,
		Client: SupervisorVMConfig{
			Role: "client", VMName: ClientVMName,
			PlatformUUID:       testClientUUID,
			SSHHostFingerprint: "SHA256:client-host-key",
			MAC:                testClientMAC,
			IPv4:               testClientIP.String(),
		},
		Peer: SupervisorVMConfig{
			Role: "peer", VMName: PeerVMName,
			PlatformUUID:       testPeerUUID,
			SSHHostFingerprint: "SHA256:peer-host-key",
			MAC:                testPeerMAC,
			IPv4:               testPeerIP.String(),
		},
	}
}

func TestPeerRuntimeObservationBindsExactVirtualMacAndPeerFacts(t *testing.T) {
	config := testPeerRuntimeConfig()
	observation := PeerRuntimeObservation{
		GOOS:                  "darwin",
		GOARCH:                "arm64",
		Model:                 "VirtualMac2,1",
		PlatformUUID:          config.Peer.PlatformUUID,
		En0MAC:                config.Peer.MAC,
		En0IPv4:               config.Peer.IPv4,
		SSHHostKeyFingerprint: config.Peer.SSHHostFingerprint,
	}
	if err := ValidatePeerRuntimeObservation(observation, config); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*PeerRuntimeObservation)
	}{
		{name: "host-hardware", mutate: func(value *PeerRuntimeObservation) {
			value.Model = "MacBookPro18,2"
		}},
		{name: "wrong-architecture", mutate: func(value *PeerRuntimeObservation) {
			value.GOARCH = "amd64"
		}},
		{name: "wrong-platform-uuid", mutate: func(value *PeerRuntimeObservation) {
			value.PlatformUUID = testClientUUID
		}},
		{name: "wrong-en0-mac", mutate: func(value *PeerRuntimeObservation) {
			value.En0MAC = testClientMAC
		}},
		{name: "wrong-en0-ip", mutate: func(value *PeerRuntimeObservation) {
			value.En0IPv4 = testClientIP.String()
		}},
		{name: "wrong-system-ssh-key", mutate: func(value *PeerRuntimeObservation) {
			value.SSHHostKeyFingerprint = "SHA256:substituted"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := observation
			test.mutate(&candidate)
			if err := ValidatePeerRuntimeObservation(candidate, config); err == nil {
				t.Fatal("wrong peer runtime identity was accepted")
			}
		})
	}
}

func TestPeerRecoveryIdentityAllowsMutableDriftButNotGuestSubstitution(t *testing.T) {
	config := testPeerRuntimeConfig()
	recovery := PeerRecoveryRuntimeObservation{
		GOOS:         "darwin",
		GOARCH:       "arm64",
		Model:        "VirtualMac2,1",
		PlatformUUID: config.Peer.PlatformUUID,
	}
	if err := ValidatePeerRecoveryRuntimeObservation(
		recovery,
		config,
	); err != nil {
		t.Fatal(err)
	}
	drifted := PeerRuntimeObservation{
		GOOS:                  recovery.GOOS,
		GOARCH:                recovery.GOARCH,
		Model:                 recovery.Model,
		PlatformUUID:          recovery.PlatformUUID,
		En0MAC:                config.Client.MAC,
		En0IPv4:               config.Client.IPv4,
		SSHHostKeyFingerprint: config.Client.SSHHostFingerprint,
	}
	if err := ValidatePeerRuntimeObservation(drifted, config); err == nil {
		t.Fatal("mutable peer identity drift was accepted for a new run")
	}
	for name, mutate := range map[string]func(*PeerRecoveryRuntimeObservation){
		"host": func(value *PeerRecoveryRuntimeObservation) {
			value.Model = "MacBookPro18,2"
		},
		"architecture": func(value *PeerRecoveryRuntimeObservation) {
			value.GOARCH = "amd64"
		},
		"platform-uuid": func(value *PeerRecoveryRuntimeObservation) {
			value.PlatformUUID = config.Client.PlatformUUID
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := recovery
			mutate(&candidate)
			if err := ValidatePeerRecoveryRuntimeObservation(
				candidate,
				config,
			); err == nil {
				t.Fatal("guest substitution was accepted for recovery")
			}
		})
	}
}
