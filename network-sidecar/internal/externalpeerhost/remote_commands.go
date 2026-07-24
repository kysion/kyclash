package externalpeerhost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/externalpeergueststaging"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
)

const (
	remoteActionRead   = "read"
	remoteActionCreate = "create"
)

type remoteFileContract struct {
	role        string
	path        string
	owner       uint32
	mode        uint32
	parentOwner uint32
	parentMode  uint32
	maximum     int
	read        bool
	create      bool
}

func remoteContracts(
	consoleUID uint32,
) map[string]remoteFileContract {
	values := make(map[string]remoteFileContract)
	add := func(value remoteFileContract) {
		values[value.role+"|"+value.path] = value
	}
	add(remoteFileContract{
		role: "client", path: filepath.Join(
			vmexternalpeerlab.ClientOutboxRoot,
			vmexternalpeerlab.ClientReadyName,
		),
		owner: 0, mode: 0o444,
		parentOwner: 0, parentMode: 0o711,
		maximum: 0, read: true,
	})
	for _, value := range []struct {
		role string
		root string
	}{
		{"client", externalpeergueststaging.ClientReviewRoot},
		{"peer", externalpeergueststaging.PeerReviewRoot},
	} {
		add(remoteFileContract{
			role: value.role,
			path: filepath.Join(
				value.root,
				externalpeergueststaging.VMIdentityWitnessName,
			),
			owner: 0, mode: 0o444,
			parentOwner: 0, parentMode: 0o755,
			maximum: externalpeer.MaxDescriptorSize,
			read:    true,
		})
	}
	for index, name := range []string{
		externalpeer.ClientArtifactNames[0],
		externalpeer.ClientArtifactNames[1],
		externalpeer.ClientArtifactNames[2],
		vmexternalpeerlab.ClientManifestName,
	} {
		maximum := externalpeer.MaxArtifactSize
		if index == 0 || index == 3 {
			maximum = externalpeer.MaxDescriptorSize
		}
		add(remoteFileContract{
			role: "client", path: filepath.Join(
				vmexternalpeerlab.ClientOutboxRoot,
				name,
			),
			owner: 0, mode: 0o444,
			parentOwner: 0, parentMode: 0o711,
			maximum: maximum, read: true,
		})
	}
	add(remoteFileContract{
		role: "peer", path: externalpeer.PeerPublicStatus,
		owner: 0, mode: 0o644,
		parentOwner: 0, parentMode: 0o711,
		maximum: 1024, read: true,
	})
	for index, name := range externalpeer.PeerArtifactNames {
		maximum := externalpeer.MaxArtifactSize
		if index == 0 || index == len(externalpeer.PeerArtifactNames)-1 {
			maximum = externalpeer.MaxDescriptorSize
		}
		add(remoteFileContract{
			role: "peer", path: filepath.Join(externalpeer.PeerPublicOutbox, name),
			owner: 0, mode: 0o644,
			parentOwner: 0, parentMode: 0o711,
			maximum: maximum, read: true,
		})
	}
	peerCreates := []struct {
		path    string
		maximum int
	}{
		{externalpeer.PeerRunTicketEnvelope, externalpeer.MaxChildControlFrame},
		{filepath.Join(externalpeer.PeerCourierInbox, externalpeer.ClientArtifactNames[0]), externalpeer.MaxDescriptorSize},
		{filepath.Join(externalpeer.PeerCourierInbox, externalpeer.ClientArtifactNames[1]), externalpeer.MaxArtifactSize},
		{filepath.Join(externalpeer.PeerCourierInbox, externalpeer.ClientArtifactNames[2]), externalpeer.MaxArtifactSize},
		{externalpeer.PeerClientTransferManifest, externalpeer.MaxDescriptorSize},
		{externalpeer.PeerClientEnvelope, externalpeer.MaxChildControlFrame},
		{externalpeer.PeerWakeTrigger, 0},
		{externalpeer.PeerCancelEnvelope, externalpeer.MaxChildControlFrame},
		{externalpeer.PeerCancelTrigger, 0},
	}
	for _, value := range peerCreates {
		add(remoteFileContract{
			role: "peer", path: value.path, owner: consoleUID,
			mode: 0o600, parentOwner: consoleUID, parentMode: 0o700,
			maximum: value.maximum, create: true,
		})
	}
	clientCreates := []struct {
		name    string
		maximum int
	}{
		{vmexternalpeerlab.RunTicketName, externalpeer.MaxChildControlFrame},
		{vmexternalpeerlab.ClientEnvelopeName, externalpeer.MaxChildControlFrame},
	}
	for index, name := range externalpeer.PeerArtifactNames {
		maximum := externalpeer.MaxArtifactSize
		if index == 0 || index == len(externalpeer.PeerArtifactNames)-1 {
			maximum = externalpeer.MaxDescriptorSize
		}
		clientCreates = append(clientCreates, struct {
			name    string
			maximum int
		}{name, maximum})
	}
	clientCreates = append(clientCreates,
		struct {
			name    string
			maximum int
		}{vmexternalpeerlab.PeerEnvelopeName, externalpeer.MaxChildControlFrame},
		struct {
			name    string
			maximum int
		}{vmexternalpeerlab.PeerReadyName, 0},
	)
	for _, value := range clientCreates {
		add(remoteFileContract{
			role: "client", path: filepath.Join(
				vmexternalpeerlab.ClientInboxRoot,
				value.name,
			),
			owner: consoleUID, mode: 0o600,
			parentOwner: consoleUID, parentMode: 0o700,
			maximum: value.maximum, create: true,
		})
	}
	return values
}

func lookupRemoteContract(
	consoleUID uint32,
	role string,
	path string,
	action string,
) (remoteFileContract, error) {
	value, exists := remoteContracts(consoleUID)[role+"|"+path]
	if !exists ||
		(action == remoteActionRead && !value.read) ||
		(action == remoteActionCreate && !value.create) ||
		(action != remoteActionRead && action != remoteActionCreate) {
		return remoteFileContract{}, ErrUnsafeHostCourier
	}
	return value, nil
}

func (runner *StartLabRunner) runRemote(
	ctx context.Context,
	roleName string,
	path string,
	action string,
	input []byte,
) ([]byte, bool, error) {
	role, err := runner.management.role(roleName)
	if err != nil {
		return nil, false, err
	}
	contract, err := lookupRemoteContract(
		role.consoleUID,
		roleName,
		path,
		action,
	)
	if err != nil || len(input) > contract.maximum ||
		action == remoteActionRead && len(input) != 0 {
		return nil, false, ErrUnsafeHostCourier
	}
	wall, _, err := runner.sampleTime()
	if err != nil {
		return nil, false, err
	}
	tartPath, err := runner.tart.Resolve()
	if err != nil {
		return nil, false, err
	}
	tartResult, err := runner.executor.Run(ctx, CommandSpec{
		Purpose: CommandTartARP, Executable: tartPath,
		Arguments:        []string{"ip", role.vmName, "--resolver=arp"},
		Environment:      append([]string(nil), fixedCommandEnvironment...),
		WorkingDirectory: "/", MaximumOutput: 128,
		Role: roleName,
	})
	if err != nil {
		return nil, false, ErrUnsafeHostCourier
	}
	resolvedIP, err := parseTartARP(tartResult.Stdout)
	clear(tartResult.Stdout)
	if err != nil ||
		resolvedIP != netip.AddrFrom4(role.facts.IPv4) ||
		runner.management.revalidate() != nil {
		return nil, false, ErrUnsafeHostCourier
	}
	remoteCommand := buildRemoteCommand(role, contract, action, wall)
	purpose := CommandRemoteRead
	if action == remoteActionCreate {
		purpose = CommandRemoteCreate
	}
	result, err := runner.executor.Run(ctx, CommandSpec{
		Purpose: purpose, Executable: fixedSSHPath,
		Arguments:        sshArguments(role, resolvedIP, remoteCommand),
		Environment:      append([]string(nil), fixedCommandEnvironment...),
		WorkingDirectory: "/", Stdin: append([]byte(nil), input...),
		MaximumOutput: contract.maximum + 4096,
		Role:          roleName, RemotePath: path,
	})
	if err != nil {
		var exit *CommandExitError
		if action == remoteActionRead &&
			errors.As(err, &exit) &&
			exit.Code == 44 {
			return nil, false, nil
		}
		return nil, false, ErrUnsafeHostCourier
	}
	defer clear(result.Stdout)
	payload, err := decodeRemoteFrame(
		result.Stdout,
		role,
		wall,
		contract.maximum,
	)
	if err != nil || runner.management.revalidate() != nil {
		clear(payload)
		return nil, false, ErrUnsafeHostCourier
	}
	return payload, true, nil
}

func parseTartARP(data []byte) (netip.Addr, error) {
	value := strings.TrimSuffix(string(data), "\n")
	if value == "" ||
		strings.ContainsAny(value, " \t\r\n\x00") {
		return netip.Addr{}, ErrUnsafeHostCourier
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() ||
		netip.MustParsePrefix("10.88.0.0/24").Contains(address) {
		return netip.Addr{}, ErrUnsafeHostCourier
	}
	return address, nil
}

func sshArguments(
	role roleContract,
	address netip.Addr,
	remoteCommand string,
) []string {
	return []string{
		"-F", "/dev/null",
		"-4",
		"-i", role.privateKey,
		"-o", "BatchMode=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + role.knownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "HostKeyAlias=" + role.vmName,
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
		managementConsoleUser + "@" + address.String(),
		remoteCommand,
	}
}

func buildRemoteCommand(
	role roleContract,
	contract remoteFileContract,
	action string,
	hostWall time.Time,
) string {
	values := []string{
		"/usr/bin/python3",
		"-c",
		remotePythonProgram,
		action,
		contract.path,
		role.facts.PlatformUUID,
		net.HardwareAddr(role.facts.MAC[:]).String(),
		netip.AddrFrom4(role.facts.IPv4).String(),
		role.facts.SSHHostFingerprint,
		strconv.FormatUint(uint64(role.consoleUID), 10),
		managementConsoleUser,
		strconv.FormatInt(hostWall.Unix(), 10),
		strconv.FormatUint(uint64(contract.owner), 10),
		fmt.Sprintf("%04o", contract.mode),
		strconv.Itoa(contract.maximum),
		strconv.FormatUint(uint64(contract.parentOwner), 10),
		fmt.Sprintf("%04o", contract.parentMode),
	}
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, shellQuote(value))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
