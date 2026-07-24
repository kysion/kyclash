package vmnetworklab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

var ErrMihomoIdentity = errors.New("Mihomo fixture identity failed")

// ExpectedMihomoSHA256 is injected by the host-only builder from the fixed
// Apple-Silicon input. An empty value intentionally fails closed at guest
// runtime; no unverified binary may be executed.
var ExpectedMihomoSHA256 = ""

// MihomoContract seals the fixed filesystem/config identity used by one lab
// composition. The legacy VM-network lab uses DefaultMihomoContract; the
// external-peer sibling supplies its own disjoint root without making any
// path caller-controlled.
type MihomoContract struct {
	StageRoot     string
	StateRoot     string
	StateRootMode os.FileMode
	SocketPath    string
	Executable    string
	ConfigPath    string
	ConfigSHA256  string
}

func DefaultMihomoContract() MihomoContract {
	return MihomoContract{
		StageRoot: StageRoot, StateRoot: StateRoot, SocketPath: MihomoSocket,
		StateRootMode: 0o700, Executable: MihomoPath, ConfigPath: MihomoConfig, ConfigSHA256: ConfigSHA256,
	}
}

func (contract MihomoContract) valid() bool {
	return contract.StageRoot != "" && contract.StateRoot != "" &&
		(contract.StateRootMode == 0o700 || contract.StateRootMode == 0o711) &&
		contract.SocketPath == contract.StateRoot+"/mihomo.sock" &&
		contract.Executable == contract.StageRoot+"/mihomo" &&
		contract.ConfigPath == contract.StageRoot+"/mihomo-config.json" &&
		validSHA256(contract.ConfigSHA256)
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func validateMihomoConfigBytes(encoded []byte, contract MihomoContract) error {
	if !contract.valid() {
		return ErrMihomoIdentity
	}
	if len(encoded) == 0 || len(encoded) > 128*1024 {
		return errors.New("Mihomo config size is invalid")
	}
	if actual := sha256.Sum256(encoded); hex.EncodeToString(actual[:]) != contract.ConfigSHA256 {
		return errors.New("Mihomo config hash mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var config mihomoConfig
	if err := decoder.Decode(&config); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("Mihomo config is malformed")
	}
	if err := config.validate(contract); err != nil {
		return err
	}
	return nil
}

type mihomoConfig struct {
	AllowLAN           bool              `json:"allow-lan"`
	BindAddress        string            `json:"bind-address"`
	Mode               string            `json:"mode"`
	LogLevel           string            `json:"log-level"`
	IPv6               bool              `json:"ipv6"`
	ExternalController string            `json:"external-controller-unix"`
	Profile            mihomoProfile     `json:"profile"`
	Tun                mihomoTun         `json:"tun"`
	Proxies            []json.RawMessage `json:"proxies"`
	ProxyGroups        []json.RawMessage `json:"proxy-groups"`
	Rules              []string          `json:"rules"`
}

type mihomoProfile struct {
	StoreSelected bool `json:"store-selected"`
	StoreFakeIP   bool `json:"store-fake-ip"`
}

type mihomoTun struct {
	Enable              bool     `json:"enable"`
	Device              string   `json:"device"`
	Stack               string   `json:"stack"`
	AutoRoute           bool     `json:"auto-route"`
	AutoDetectInterface bool     `json:"auto-detect-interface"`
	StrictRoute         bool     `json:"strict-route"`
	MTU                 int      `json:"mtu"`
	Inet4Address        []string `json:"inet4-address"`
	RouteAddress        []string `json:"route-address"`
}

func (config mihomoConfig) validate(contract MihomoContract) error {
	if config.AllowLAN || config.BindAddress != "127.0.0.1" || config.Mode != "direct" || config.IPv6 || config.ExternalController != contract.SocketPath {
		return errors.New("Mihomo config widens the fixed lab authority")
	}
	if config.Profile.StoreSelected || config.Profile.StoreFakeIP || len(config.Proxies) != 0 || len(config.ProxyGroups) != 0 || len(config.Rules) != 1 || config.Rules[0] != "MATCH,DIRECT" {
		return errors.New("Mihomo config contains non-fixed behavior")
	}
	if !config.Tun.Enable || config.Tun.Device != MihomoInterface || config.Tun.Stack != "system" || !config.Tun.AutoRoute || !config.Tun.AutoDetectInterface || config.Tun.StrictRoute || config.Tun.MTU != 1420 || !equalStrings(config.Tun.Inet4Address, []string{"198.18.0.1/30"}) || !equalStrings(config.Tun.RouteAddress, []string{CoveringCIDR}) {
		return errors.New("Mihomo TUN config is not the fixed coexistence fixture")
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateMihomoConfigFile(path string, requireRoot bool, contract MihomoContract) error {
	if path != contract.ConfigPath || !contract.valid() {
		return ErrMihomoIdentity
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return ErrMihomoIdentity
	}
	if requireRoot {
		if !isRootOwned(info) {
			return ErrMihomoIdentity
		}
	}
	encoded, err := os.ReadFile(path)
	if err != nil || validateMihomoConfigBytes(encoded, contract) != nil {
		return ErrMihomoIdentity
	}
	return nil
}

func validateMihomoExecutable(path string, requireRoot bool) (string, fileIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return "", fileIdentity{}, ErrMihomoIdentity
	}
	if requireRoot && !isRootOwned(info) {
		return "", fileIdentity{}, ErrMihomoIdentity
	}
	digest, err := sha256File(path)
	if err != nil || !validSHA256(digest) || ExpectedMihomoSHA256 == "" || !strings.EqualFold(digest, ExpectedMihomoSHA256) {
		return "", fileIdentity{}, ErrMihomoIdentity
	}
	identity, err := getFileIdentity(info)
	if err != nil {
		return "", fileIdentity{}, ErrMihomoIdentity
	}
	return digest, identity, nil
}

func isRootOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

type fileIdentity struct {
	dev   uint64
	inode uint64
}

func getFileIdentity(info os.FileInfo) (fileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		return fileIdentity{}, ErrMihomoIdentity
	}
	return fileIdentity{dev: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func validateMachOArm64(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return ErrMihomoIdentity
	}
	defer file.Close()
	header := make([]byte, 8)
	if _, err := io.ReadFull(file, header); err != nil {
		return ErrMihomoIdentity
	}
	// Thin 64-bit little-endian Mach-O, CPU_TYPE_ARM64.
	if !bytes.Equal(header[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) || !bytes.Equal(header[4:8], []byte{0x0c, 0x00, 0x00, 0x01}) {
		return fmt.Errorf("%w: not a thin arm64 Mach-O", ErrMihomoIdentity)
	}
	return nil
}
