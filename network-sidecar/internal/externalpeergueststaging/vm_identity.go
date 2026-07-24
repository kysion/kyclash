package externalpeergueststaging

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
)

var platformUUIDPattern = regexp.MustCompile(
	`(?m)"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"`,
)

// VMIdentity is the live, guest-observed identity used to prevent a
// role-specific staging binary from being replayed in another VirtualMac.
// IPv4 is intentionally included even though it may change between isolated
// Layer A and bridged Layer B; callers choose immutable-only or full equality.
type VMIdentity struct {
	Model                  string `json:"model"`
	Architecture           string `json:"architecture"`
	PlatformUUID           string `json:"platform_uuid"`
	En0MAC                 string `json:"en0_mac"`
	En0IPv4                string `json:"en0_ipv4"`
	SSHHostPublicKeySHA256 string `json:"ssh_host_public_key_sha256"`
	SSHHostKeyFingerprint  string `json:"ssh_host_key_fingerprint"`
}

func (value VMIdentity) Validate() error {
	if !strings.HasPrefix(strings.TrimSpace(value.Model), "VirtualMac") ||
		value.Architecture != "arm64" ||
		!validPlatformUUID(value.PlatformUUID) ||
		!validMAC(value.En0MAC) ||
		!validPrivateIPv4(value.En0IPv4) ||
		!validSHA256(value.SSHHostPublicKeySHA256) ||
		!strings.HasPrefix(value.SSHHostKeyFingerprint, "SHA256:") {
		return ErrGuestStaging
	}
	return nil
}

func (value VMIdentity) equalImmutable(other VMIdentity) bool {
	return value.Validate() == nil &&
		other.Validate() == nil &&
		value.Model == other.Model &&
		value.Architecture == other.Architecture &&
		strings.EqualFold(value.PlatformUUID, other.PlatformUUID) &&
		strings.EqualFold(value.En0MAC, other.En0MAC)
}

func (value VMIdentity) equalFull(other VMIdentity) bool {
	return value.equalImmutable(other) &&
		value.En0IPv4 == other.En0IPv4 &&
		value.SSHHostPublicKeySHA256 == other.SSHHostPublicKeySHA256 &&
		value.SSHHostKeyFingerprint == other.SSHHostKeyFingerprint
}

func validPlatformUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func validMAC(value string) bool {
	parsed, err := net.ParseMAC(value)
	return err == nil && len(parsed) == 6 &&
		strings.ToLower(parsed.String()) == strings.ToLower(value)
}

func validPrivateIPv4(value string) bool {
	parsed, err := netip.ParseAddr(value)
	return err == nil && parsed.Is4() && parsed.IsPrivate()
}

type VMIdentityCollector func(context.Context) (VMIdentity, error)

func collectProductionVMIdentity(parent context.Context) (VMIdentity, error) {
	ctx := parent
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	model, err := readVirtualMacModel()
	if err != nil {
		return VMIdentity{}, err
	}
	ioreg, err := runFixedCommand(
		ctx,
		"/usr/sbin/ioreg",
		"-rd1",
		"-c",
		"IOPlatformExpertDevice",
	)
	if err != nil {
		return VMIdentity{}, err
	}
	match := platformUUIDPattern.FindSubmatch(ioreg)
	clear(ioreg)
	if len(match) != 2 {
		return VMIdentity{}, ErrGuestStaging
	}
	platformUUID := strings.ToUpper(string(match[1]))

	ifconfig, err := runFixedCommand(ctx, "/sbin/ifconfig", "en0")
	if err != nil {
		return VMIdentity{}, err
	}
	mac, ipv4, err := parseEn0Identity(ifconfig)
	clear(ifconfig)
	if err != nil {
		return VMIdentity{}, err
	}
	hostRaw, hostFingerprint, err := readCanonicalSystemHostPublicKey()
	if err != nil {
		return VMIdentity{}, err
	}
	defer clear(hostRaw)
	result := VMIdentity{
		Model:                  model,
		Architecture:           "arm64",
		PlatformUUID:           platformUUID,
		En0MAC:                 mac,
		En0IPv4:                ipv4,
		SSHHostPublicKeySHA256: hashHex(hostRaw),
		SSHHostKeyFingerprint:  hostFingerprint,
	}
	if result.Validate() != nil {
		return VMIdentity{}, ErrGuestStaging
	}
	return result, nil
}

func parseEn0Identity(data []byte) (string, string, error) {
	if len(data) == 0 || len(data) > sshBootstrapMaxFile ||
		bytes.Contains(data, []byte{0}) {
		return "", "", ErrGuestStaging
	}
	var mac string
	var ipv4 string
	for _, raw := range strings.Split(string(data), "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "ether":
			parsed, err := net.ParseMAC(fields[1])
			if err != nil || len(parsed) != 6 || mac != "" {
				return "", "", ErrGuestStaging
			}
			mac = strings.ToLower(parsed.String())
		case "inet":
			parsed, err := netip.ParseAddr(fields[1])
			if err == nil && parsed.Is4() && parsed.IsPrivate() {
				if ipv4 != "" {
					return "", "", ErrGuestStaging
				}
				ipv4 = parsed.String()
			}
		}
	}
	if !validMAC(mac) || !validPrivateIPv4(ipv4) {
		return "", "", ErrGuestStaging
	}
	return mac, ipv4, nil
}

type vmIdentityWitness struct {
	SchemaVersion     uint8      `json:"schema_version"`
	Role              Role       `json:"role"`
	RuntimeTarget     string     `json:"runtime_target"`
	CollectedAt       int64      `json:"collected_at"`
	Identity          VMIdentity `json:"identity"`
	AppTreeSHA256     string     `json:"app_tree_sha256,omitempty"`
	AppManifestSHA256 string     `json:"app_tree_manifest_sha256,omitempty"`
}

func (value vmIdentityWitness) Validate() error {
	expectedTarget := map[Role]string{
		ClientRole: "kyclash-macos-lab-work",
		PeerRole:   "kyclash-macos-lab-peer",
	}[value.Role]
	if value.SchemaVersion != 1 ||
		expectedTarget == "" ||
		value.RuntimeTarget != expectedTarget ||
		value.CollectedAt <= 0 ||
		value.Identity.Validate() != nil ||
		(value.Role == ClientRole && !validSHA256(value.AppTreeSHA256)) ||
		(value.Role == ClientRole && !validSHA256(value.AppManifestSHA256)) ||
		(value.Role == PeerRole && value.AppTreeSHA256 != "") ||
		(value.Role == PeerRole && value.AppManifestSHA256 != "") {
		return ErrGuestStaging
	}
	return nil
}

func encodeVMIdentityWitness(value vmIdentityWitness) ([]byte, error) {
	if value.Validate() != nil {
		return nil, ErrGuestStaging
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > externalpeer.MaxDescriptorSize {
		return nil, ErrGuestStaging
	}
	return append(encoded, '\n'), nil
}

func decodeVMIdentityWitness(data []byte) (vmIdentityWitness, error) {
	if len(data) == 0 || len(data) > externalpeer.MaxDescriptorSize {
		return vmIdentityWitness{}, ErrGuestStaging
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value vmIdentityWitness
	if decoder.Decode(&value) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		value.Validate() != nil {
		return vmIdentityWitness{}, ErrGuestStaging
	}
	return value, nil
}
