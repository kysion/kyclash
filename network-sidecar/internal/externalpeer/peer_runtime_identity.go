package externalpeer

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
)

// PeerRuntimeObservation is the complete live identity boundary that a peer
// root supervisor must bind before recovery/readiness and again immediately
// before starting the unprivileged child.
type PeerRuntimeObservation struct {
	GOOS                  string
	GOARCH                string
	Model                 string
	PlatformUUID          string
	En0MAC                string
	En0IPv4               string
	SSHHostKeyFingerprint string
}

// PeerRecoveryRuntimeObservation contains only the immutable facts needed to
// prove that retained root state belongs to the reviewed peer VM. Mutable
// network/sshd facts are deliberately excluded so drift cannot prevent cleanup.
type PeerRecoveryRuntimeObservation struct {
	GOOS         string
	GOARCH       string
	Model        string
	PlatformUUID string
}

func ValidatePeerRecoveryRuntimeObservation(
	observation PeerRecoveryRuntimeObservation,
	config PeerSupervisorConfig,
) error {
	if config.Validate() != nil ||
		observation.GOOS != "darwin" ||
		observation.GOARCH != "arm64" ||
		!strings.HasPrefix(strings.TrimSpace(observation.Model), "VirtualMac") ||
		!strings.EqualFold(
			strings.TrimSpace(observation.PlatformUUID),
			config.Peer.PlatformUUID,
		) {
		return ErrSupervisorState
	}
	return nil
}

func ValidatePeerRuntimeObservation(
	observation PeerRuntimeObservation,
	config PeerSupervisorConfig,
) error {
	if ValidatePeerRecoveryRuntimeObservation(
		PeerRecoveryRuntimeObservation{
			GOOS:         observation.GOOS,
			GOARCH:       observation.GOARCH,
			Model:        observation.Model,
			PlatformUUID: observation.PlatformUUID,
		},
		config,
	) != nil ||
		observation.SSHHostKeyFingerprint !=
			config.Peer.SSHHostFingerprint {
		return ErrSupervisorState
	}
	observedIP, ipErr := netip.ParseAddr(observation.En0IPv4)
	expectedIP, expectedIPErr := netip.ParseAddr(config.Peer.IPv4)
	observedMAC, macErr := net.ParseMAC(observation.En0MAC)
	expectedMAC, expectedMACErr := net.ParseMAC(config.Peer.MAC)
	if ipErr != nil ||
		expectedIPErr != nil ||
		observedIP.Unmap() != expectedIP.Unmap() ||
		!validPrivateAddr(observedIP.Unmap()) ||
		macErr != nil ||
		expectedMACErr != nil ||
		len(observedMAC) != 6 ||
		len(expectedMAC) != 6 ||
		!bytes.Equal(observedMAC, expectedMAC) {
		return ErrSupervisorState
	}
	return nil
}

func ValidateCurrentPeerRecoveryRuntime(config PeerSupervisorConfig) error {
	observation, err := observeCurrentPeerRecoveryRuntime(config)
	if err != nil {
		return err
	}
	return ValidatePeerRecoveryRuntimeObservation(observation, config)
}

func ValidateCurrentPeerRuntime(config PeerSupervisorConfig) error {
	observation, err := observeCurrentPeerRuntime(config)
	if err != nil {
		return err
	}
	return ValidatePeerRuntimeObservation(observation, config)
}
