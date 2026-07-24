package externalpeerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	fixedTartRelativePath       = "target/tools/tart-2.32.1/tart.app/Contents/MacOS/tart"
	fixedTartSHA256             = "05b65d5c14e8b41e8e44b6d9fd1278de4bedbc8b735d9b99f3c748f76f75862d"
	fixedTartSize         int64 = 72771024
	fixedSSHPath                = "/usr/bin/ssh"
	maxCommandOutput            = maximumHostArtifactBytes + 4096
)

var fixedCommandEnvironment = []string{
	"LANG=C",
	"LC_ALL=C",
	"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
}

type CommandPurpose uint8

const (
	CommandTartARP CommandPurpose = iota + 1
	CommandRemoteRead
	CommandRemoteCreate
)

type CommandSpec struct {
	Purpose          CommandPurpose
	Executable       string
	Arguments        []string
	Environment      []string
	WorkingDirectory string
	Stdin            []byte
	MaximumOutput    int
	Role             string
	RemotePath       string
}

type CommandResult struct {
	Stdout []byte
}

type CommandExecutor interface {
	Run(context.Context, CommandSpec) (CommandResult, error)
}

type CommandExitError struct {
	Code int
}

func (failure *CommandExitError) Error() string {
	return "fixed host command failed"
}

type OSCommandExecutor struct {
	tartPath string
}

func NewOSCommandExecutor(layout Layout) (*OSCommandExecutor, error) {
	tartPath, err := fixedTartPath(layout)
	if err != nil {
		return nil, err
	}
	return &OSCommandExecutor{tartPath: tartPath}, nil
}

func (executor *OSCommandExecutor) Run(
	ctx context.Context,
	spec CommandSpec,
) (CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if executor == nil ||
		validateCommandSpec(spec, executor.tartPath) != nil {
		return CommandResult{}, ErrUnsafeHostCourier
	}
	if spec.Purpose == CommandTartARP &&
		verifyFixedTartExecutable(executor.tartPath, fixedTartSHA256, fixedTartSize) != nil {
		return CommandResult{}, ErrUnsafeHostCourier
	}
	command := exec.CommandContext(ctx, spec.Executable, spec.Arguments...)
	command.Env = append([]string(nil), spec.Environment...)
	command.Dir = spec.WorkingDirectory
	command.Stdin = bytes.NewReader(spec.Stdin)
	stdout := &boundedCommandBuffer{maximum: spec.MaximumOutput}
	stderr := &boundedCommandBuffer{maximum: 4096}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	clear(stderr.bytes)
	if err != nil {
		clear(stdout.bytes)
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return CommandResult{}, &CommandExitError{Code: exitError.ExitCode()}
		}
		return CommandResult{}, ErrUnsafeHostCourier
	}
	return CommandResult{Stdout: stdout.bytes}, nil
}

func validateCommandSpec(spec CommandSpec, tartPath string) error {
	if !filepath.IsAbs(spec.Executable) ||
		spec.WorkingDirectory != "/" ||
		spec.MaximumOutput <= 0 ||
		spec.MaximumOutput > maxCommandOutput ||
		!equalStrings(spec.Environment, fixedCommandEnvironment) ||
		len(spec.Arguments) == 0 ||
		len(spec.Arguments) > 96 ||
		len(spec.Stdin) > maximumHostArtifactBytes {
		return ErrUnsafeHostCourier
	}
	switch spec.Purpose {
	case CommandTartARP:
		if spec.Executable != tartPath ||
			!strings.HasSuffix(
				spec.Executable,
				filepath.FromSlash("/"+fixedTartRelativePath),
			) ||
			len(spec.Stdin) != 0 ||
			spec.RemotePath != "" ||
			(spec.Role != "client" && spec.Role != "peer") ||
			len(spec.Arguments) != 3 ||
			spec.Arguments[0] != "ip" ||
			spec.Arguments[2] != "--resolver=arp" ||
			spec.Role == "client" &&
				spec.Arguments[1] != "kyclash-macos-lab-work" ||
			spec.Role == "peer" &&
				spec.Arguments[1] != "kyclash-macos-lab-peer" {
			return ErrUnsafeHostCourier
		}
	case CommandRemoteRead, CommandRemoteCreate:
		if spec.Executable != fixedSSHPath ||
			(spec.Role != "client" && spec.Role != "peer") ||
			!filepath.IsAbs(spec.RemotePath) ||
			validateFixedSSHArguments(spec, tartPath) != nil {
			return ErrUnsafeHostCourier
		}
	default:
		return ErrUnsafeHostCourier
	}
	return nil
}

func validateFixedSSHArguments(spec CommandSpec, tartPath string) error {
	repositoryRoot, err := fixedRepositoryRootFromTart(tartPath)
	if err != nil {
		return err
	}
	vmName := "kyclash-macos-lab-work"
	privateKeyName := ClientManagementKeyName
	knownHostsName := ClientKnownHostsName
	if spec.Role == "peer" {
		vmName = "kyclash-macos-lab-peer"
		privateKeyName = PeerManagementKeyName
		knownHostsName = PeerKnownHostsName
	}
	privateKey := filepath.Join(
		repositoryRoot,
		filepath.FromSlash(PrivateRelativeRoot),
		ManagementDirectoryName,
		privateKeyName,
	)
	knownHosts := filepath.Join(
		repositoryRoot,
		filepath.FromSlash(PrivateRelativeRoot),
		ManagementDirectoryName,
		knownHostsName,
	)
	prefix := []string{
		"-F", "/dev/null",
		"-4",
		"-i", privateKey,
		"-o", "BatchMode=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "HostKeyAlias=" + vmName,
		"-o", "CheckHostIP=no",
		"-o", "CanonicalizeHostname=no",
		"-o", "ConnectionAttempts=1",
		"-o", "ConnectTimeout=5",
		"-o", "ServerAliveInterval=2",
		"-o", "ServerAliveCountMax=2",
		"-o", "ClearAllForwardings=yes",
		"-o", "ForwardAgent=no",
		"-o", "RequestTTY=no",
		"-o", "PermitLocalCommand=no",
		"-o", "ProxyCommand=none",
		"-o", "ProxyJump=none",
		"-o", "ControlMaster=no",
		"-o", "LogLevel=ERROR",
		"--",
	}
	if len(spec.Arguments) != len(prefix)+2 ||
		!equalStrings(spec.Arguments[:len(prefix)], prefix) {
		return ErrUnsafeHostCourier
	}
	addressText, ok := strings.CutPrefix(
		spec.Arguments[len(prefix)],
		managementConsoleUser+"@",
	)
	if !ok || addressText == "" ||
		strings.ContainsAny(addressText, " \t\r\n\x00:@[]") {
		return ErrUnsafeHostCourier
	}
	address, err := netip.ParseAddr(addressText)
	if err != nil || !address.Is4() || !address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() ||
		netip.MustParsePrefix("10.88.0.0/24").Contains(address) {
		return ErrUnsafeHostCourier
	}
	values, err := parseFixedShellQuotedCommand(
		spec.Arguments[len(prefix)+1],
	)
	if err != nil || len(values) != 17 ||
		values[0] != "/usr/bin/python3" ||
		values[1] != "-c" ||
		values[2] != remotePythonProgram ||
		values[4] != spec.RemotePath ||
		values[7] != address.String() ||
		values[10] != managementConsoleUser ||
		!validFixedUUID(values[5]) ||
		!validFixedMAC(values[6]) ||
		!validFixedSSHFingerprint(values[8]) {
		return ErrUnsafeHostCourier
	}
	action := remoteActionRead
	if spec.Purpose == CommandRemoteCreate {
		action = remoteActionCreate
	}
	if values[3] != action {
		return ErrUnsafeHostCourier
	}
	consoleUID, err := parseCanonicalUint(values[9], 32)
	if err != nil || consoleUID == 0 {
		return ErrUnsafeHostCourier
	}
	if _, err := parseCanonicalInt(values[11], 64); err != nil {
		return ErrUnsafeHostCourier
	}
	contract, err := lookupRemoteContract(
		uint32(consoleUID),
		spec.Role,
		spec.RemotePath,
		action,
	)
	if err != nil ||
		values[12] != strconv.FormatUint(uint64(contract.owner), 10) ||
		values[13] != fmt.Sprintf("%04o", contract.mode) ||
		values[14] != strconv.Itoa(contract.maximum) ||
		values[15] != strconv.FormatUint(uint64(contract.parentOwner), 10) ||
		values[16] != fmt.Sprintf("%04o", contract.parentMode) ||
		spec.MaximumOutput != contract.maximum+4096 ||
		action == remoteActionRead && len(spec.Stdin) != 0 ||
		action == remoteActionCreate && len(spec.Stdin) > contract.maximum {
		return ErrUnsafeHostCourier
	}
	return nil
}

func fixedRepositoryRootFromTart(tartPath string) (string, error) {
	suffix := string(os.PathSeparator) +
		filepath.FromSlash(fixedTartRelativePath)
	if !filepath.IsAbs(tartPath) ||
		filepath.Clean(tartPath) != tartPath ||
		!strings.HasSuffix(tartPath, suffix) {
		return "", ErrUnsafeHostCourier
	}
	root := strings.TrimSuffix(tartPath, suffix)
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", ErrUnsafeHostCourier
	}
	return root, nil
}

func parseFixedShellQuotedCommand(command string) ([]string, error) {
	if command == "" || len(command) > 64*1024 {
		return nil, ErrUnsafeHostCourier
	}
	values := make([]string, 0, 17)
	for offset := 0; offset < len(command); {
		if command[offset] != '\'' {
			return nil, ErrUnsafeHostCourier
		}
		offset++
		var value strings.Builder
		for {
			next := strings.IndexByte(command[offset:], '\'')
			if next < 0 {
				return nil, ErrUnsafeHostCourier
			}
			value.WriteString(command[offset : offset+next])
			offset += next
			if strings.HasPrefix(command[offset:], "'\"'\"'") {
				value.WriteByte('\'')
				offset += len("'\"'\"'")
				continue
			}
			offset++
			break
		}
		values = append(values, value.String())
		if offset == len(command) {
			break
		}
		if command[offset] != ' ' ||
			offset+1 >= len(command) ||
			command[offset+1] != '\'' {
			return nil, ErrUnsafeHostCourier
		}
		offset++
	}
	return values, nil
}

func parseCanonicalUint(value string, bits int) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, bits)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, ErrUnsafeHostCourier
	}
	return parsed, nil
}

func parseCanonicalInt(value string, bits int) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, bits)
	if err != nil || parsed <= 0 ||
		strconv.FormatInt(parsed, 10) != value {
		return 0, ErrUnsafeHostCourier
	}
	return parsed, nil
}

func validFixedUUID(value string) bool {
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

func validFixedMAC(value string) bool {
	parsed, err := net.ParseMAC(value)
	return err == nil && len(parsed) == 6 &&
		parsed.String() == strings.ToLower(value)
}

func validFixedSSHFingerprint(value string) bool {
	encoded, ok := strings.CutPrefix(value, "SHA256:")
	if !ok {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	valid := err == nil && len(decoded) == sha256.Size
	clear(decoded)
	return valid
}

type boundedCommandBuffer struct {
	maximum int
	bytes   []byte
}

func (buffer *boundedCommandBuffer) Write(data []byte) (int, error) {
	if buffer.maximum <= 0 ||
		len(buffer.bytes)+len(data) > buffer.maximum {
		return 0, ErrUnsafeHostCourier
	}
	buffer.bytes = append(buffer.bytes, data...)
	return len(data), nil
}

type TartResolver interface {
	Resolve() (string, error)
}

type FixedTartResolver struct {
	path string
}

func NewFixedTartResolver(layout Layout) (*FixedTartResolver, error) {
	path, err := fixedTartPath(layout)
	if err != nil {
		return nil, err
	}
	return &FixedTartResolver{path: path}, nil
}

func (resolver *FixedTartResolver) Resolve() (string, error) {
	if resolver == nil ||
		verifyFixedTartExecutable(
			resolver.path,
			fixedTartSHA256,
			fixedTartSize,
		) != nil {
		return "", ErrUnsafeHostCourier
	}
	return resolver.path, nil
}

func fixedTartPath(layout Layout) (string, error) {
	if !filepath.IsAbs(layout.RepositoryRoot) ||
		filepath.Clean(layout.RepositoryRoot) != layout.RepositoryRoot {
		return "", ErrUnsafeHostCourier
	}
	path := filepath.Join(
		layout.RepositoryRoot,
		filepath.FromSlash(fixedTartRelativePath),
	)
	if !filepath.IsAbs(path) ||
		filepath.Clean(path) != path ||
		!strings.HasPrefix(
			path,
			layout.RepositoryRoot+string(filepath.Separator),
		) {
		return "", ErrUnsafeHostCourier
	}
	return path, nil
}

func verifyFixedTartExecutable(
	path string,
	expectedSHA256 string,
	expectedSize int64,
) error {
	return verifyFixedTartExecutableWithHook(
		path,
		expectedSHA256,
		expectedSize,
		nil,
	)
}

func verifyFixedTartExecutableWithHook(
	path string,
	expectedSHA256 string,
	expectedSize int64,
	afterRead func(),
) error {
	if !filepath.IsAbs(path) ||
		filepath.Clean(path) != path ||
		!strings.HasSuffix(
			path,
			filepath.FromSlash("/"+fixedTartRelativePath),
		) ||
		expectedSHA256 == "" ||
		expectedSize <= 0 {
		return ErrUnsafeHostCourier
	}
	directories := tartParentDirectories(path)
	if len(directories) != 7 {
		return ErrUnsafeHostCourier
	}
	beforeDirectories := make([]os.FileInfo, len(directories))
	for index, directory := range directories {
		info, err := os.Lstat(directory)
		if err != nil || !safeExecutableDirectoryInfo(info) {
			return ErrUnsafeHostCourier
		}
		beforeDirectories[index] = info
	}
	before, err := os.Lstat(path)
	if err != nil ||
		!safeExecutableInfo(before) ||
		before.Size() != expectedSize {
		return ErrUnsafeHostCourier
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafeHostCourier
	}
	defer file.Close()
	openedBefore, err := file.Stat()
	if err != nil ||
		!os.SameFile(before, openedBefore) ||
		!safeExecutableInfo(openedBefore) ||
		openedBefore.Size() != expectedSize {
		return ErrUnsafeHostCourier
	}
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(file, expectedSize+1))
	if err != nil || read != expectedSize ||
		fmtHex(hash.Sum(nil)) != expectedSHA256 {
		return ErrUnsafeHostCourier
	}
	if afterRead != nil {
		afterRead()
	}
	openedAfter, statErr := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil ||
		!os.SameFile(openedBefore, openedAfter) ||
		!os.SameFile(openedAfter, pathAfter) ||
		openedBefore.Size() != openedAfter.Size() ||
		!openedBefore.ModTime().Equal(openedAfter.ModTime()) ||
		!openedAfter.ModTime().Equal(pathAfter.ModTime()) ||
		!safeExecutableInfo(openedAfter) ||
		!safeExecutableInfo(pathAfter) ||
		pathAfter.Size() != expectedSize {
		return ErrUnsafeHostCourier
	}
	for index, directory := range directories {
		after, err := os.Lstat(directory)
		if err != nil ||
			!os.SameFile(beforeDirectories[index], after) ||
			!safeExecutableDirectoryInfo(after) {
			return ErrUnsafeHostCourier
		}
	}
	return nil
}

func safeExecutableInfo(info os.FileInfo) bool {
	if info == nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o111 == 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok &&
		(stat.Uid == 0 || stat.Uid == uint32(os.Getuid())) &&
		stat.Nlink == 1
}

func safeExecutableDirectoryInfo(info os.FileInfo) bool {
	if info == nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok &&
		(stat.Uid == 0 || stat.Uid == uint32(os.Getuid())) &&
		stat.Nlink >= 1
}

func tartParentDirectories(path string) []string {
	directories := make([]string, 0, 7)
	current := filepath.Dir(path)
	for index := 0; index < 7; index++ {
		directories = append(directories, current)
		current = filepath.Dir(current)
	}
	return directories
}

func fmtHex(data []byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, len(data)*2)
	for index, value := range data {
		encoded[index*2] = digits[value>>4]
		encoded[index*2+1] = digits[value&0x0f]
	}
	return string(encoded)
}

type RunnerClock interface {
	WallNow() time.Time
	MonotonicNow() time.Duration
	Wait(context.Context, time.Duration) error
}

type SystemRunnerClock struct {
	origin time.Time
}

func NewSystemRunnerClock() *SystemRunnerClock {
	return &SystemRunnerClock{origin: time.Now()}
}

func (clock *SystemRunnerClock) WallNow() time.Time {
	return time.Now().UTC()
}

func (clock *SystemRunnerClock) MonotonicNow() time.Duration {
	if clock == nil || clock.origin.IsZero() {
		return 0
	}
	return time.Since(clock.origin)
}

func (*SystemRunnerClock) Wait(ctx context.Context, duration time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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

var _ io.Writer = (*boundedCommandBuffer)(nil)
