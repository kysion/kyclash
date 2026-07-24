//go:build darwin

package externalpeer

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

var peerPlatformUUIDPattern = regexp.MustCompile(
	`(?m)^[ \t]*"IOPlatformUUID"[ \t]*=[ \t]*"([0-9A-Fa-f-]{36})"[ \t]*$`,
)

func observeCurrentPeerRuntime(
	config PeerSupervisorConfig,
) (PeerRuntimeObservation, error) {
	recovery, err := observeCurrentPeerRecoveryRuntime(config)
	if err != nil {
		return PeerRuntimeObservation{}, err
	}
	networkInterface, err := net.InterfaceByName(BindInterface)
	if err != nil ||
		networkInterface == nil ||
		networkInterface.Flags&net.FlagUp == 0 ||
		len(networkInterface.HardwareAddr) != 6 {
		return PeerRuntimeObservation{}, ErrSupervisorState
	}
	addresses, err := networkInterface.Addrs()
	if err != nil {
		return PeerRuntimeObservation{}, ErrSupervisorState
	}
	privateIPv4 := make([]netip.Addr, 0, 1)
	for _, address := range addresses {
		prefix, parseErr := netip.ParsePrefix(address.String())
		if parseErr != nil {
			continue
		}
		candidate := prefix.Addr().Unmap()
		if candidate.Is4() &&
			validPrivateAddr(candidate) &&
			!innerPrefix().Contains(candidate) {
			privateIPv4 = append(privateIPv4, candidate)
		}
	}
	if len(privateIPv4) != 1 {
		return PeerRuntimeObservation{}, ErrSupervisorState
	}
	hostPublic, err := readSystemSSHHostPublicKey()
	if err != nil {
		return PeerRuntimeObservation{}, err
	}
	defer clear(hostPublic)
	hostKey, err := ssh.ParsePublicKey(hostPublic)
	if err != nil ||
		hostKey.Type() != ssh.KeyAlgoED25519 ||
		!bytes.Equal(hostKey.Marshal(), hostPublic) {
		return PeerRuntimeObservation{}, ErrSupervisorState
	}
	return PeerRuntimeObservation{
		GOOS:                  recovery.GOOS,
		GOARCH:                recovery.GOARCH,
		Model:                 recovery.Model,
		PlatformUUID:          recovery.PlatformUUID,
		En0MAC:                networkInterface.HardwareAddr.String(),
		En0IPv4:               privateIPv4[0].String(),
		SSHHostKeyFingerprint: ssh.FingerprintSHA256(hostKey),
	}, nil
}

func observeCurrentPeerRecoveryRuntime(
	config PeerSupervisorConfig,
) (PeerRecoveryRuntimeObservation, error) {
	if config.Validate() != nil ||
		runtime.GOOS != "darwin" ||
		runtime.GOARCH != "arm64" {
		return PeerRecoveryRuntimeObservation{}, ErrSupervisorState
	}
	model, err := unix.Sysctl("hw.model")
	if err != nil {
		return PeerRecoveryRuntimeObservation{}, ErrSupervisorState
	}
	output, err := fixedReadOnlyCommand(
		context.Background(),
		"/usr/sbin/ioreg",
		"-rd1",
		"-c",
		"IOPlatformExpertDevice",
	)
	if err != nil {
		return PeerRecoveryRuntimeObservation{}, ErrSupervisorState
	}
	matches := peerPlatformUUIDPattern.FindAllSubmatch(output, -1)
	if len(matches) != 1 || len(matches[0]) != 2 {
		clear(output)
		return PeerRecoveryRuntimeObservation{}, ErrSupervisorState
	}
	platformUUID := string(matches[0][1])
	clear(output)
	return PeerRecoveryRuntimeObservation{
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		Model:        strings.TrimSpace(model),
		PlatformUUID: platformUUID,
	}, nil
}
