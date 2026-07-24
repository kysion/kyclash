package externalpeer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrListenerAudit   = errors.New("external-peer listener audit failed")
	errConnectedSocket = errors.New("connected socket is not a listener")
)

type ListenerRecord struct {
	Protocol         string `json:"protocol"`
	BindAddress      string `json:"bind_address"`
	Port             uint16 `json:"port"`
	PID              int    `json:"pid"`
	StartIdentity    string `json:"start_identity"`
	UID              uint32 `json:"uid"`
	Command          string `json:"command"`
	ExecutablePath   string `json:"executable_path"`
	ExecutableSHA256 string `json:"executable_sha256"`
	CodeSignature    string `json:"code_signature"`
	LaunchdLabel     string `json:"launchd_label"`
}

type ListenerInventory struct {
	SchemaVersion uint8            `json:"schema_version"`
	CollectedAt   int64            `json:"collected_at"`
	Listeners     []ListenerRecord `json:"listeners"`
}

type ListenerAllowance struct {
	Protocol         string `json:"protocol"`
	BindAddress      string `json:"bind_address"`
	Port             uint16 `json:"port"`
	UID              uint32 `json:"uid"`
	Command          string `json:"command"`
	ExecutablePath   string `json:"executable_path"`
	ExecutableSHA256 string `json:"executable_sha256"`
	CodeSignature    string `json:"code_signature"`
	LaunchdLabel     string `json:"launchd_label"`
	LaunchdPID1      bool   `json:"launchd_pid1"`
}

func DecodeListenerInventory(data []byte) (ListenerInventory, error) {
	if len(data) == 0 ||
		len(data) > MaxChildControlFrame ||
		rejectDuplicateObjectKeys(data) != nil {
		return ListenerInventory{}, ErrListenerAudit
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var inventory ListenerInventory
	if decoder.Decode(&inventory) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		inventory.SchemaVersion != SchemaVersion ||
		inventory.CollectedAt <= 0 ||
		len(inventory.Listeners) > 512 {
		return ListenerInventory{}, ErrListenerAudit
	}
	for _, record := range inventory.Listeners {
		if record.PID < 1 ||
			record.StartIdentity == "" ||
			len(record.StartIdentity) > 128 {
			return ListenerInventory{}, ErrListenerAudit
		}
		allowance := ListenerAllowance{
			Protocol:         record.Protocol,
			BindAddress:      record.BindAddress,
			Port:             record.Port,
			UID:              record.UID,
			Command:          record.Command,
			ExecutablePath:   record.ExecutablePath,
			ExecutableSHA256: record.ExecutableSHA256,
			CodeSignature:    record.CodeSignature,
			LaunchdLabel:     record.LaunchdLabel,
			LaunchdPID1:      record.PID == 1,
		}
		if validateListenerAllowance(allowance) != nil {
			return ListenerInventory{}, ErrListenerAudit
		}
	}
	return inventory, nil
}

func CollectListenerInventory(ctx context.Context) (ListenerInventory, error) {
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 {
		return ListenerInventory{}, ErrListenerAudit
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var records []ListenerRecord
	for _, query := range []struct {
		family    int
		arguments []string
	}{
		{4, []string{"-nP", "-a", "-i4TCP", "-sTCP:LISTEN", "-F0pcuPn"}},
		{6, []string{"-nP", "-a", "-i6TCP", "-sTCP:LISTEN", "-F0pcuPn"}},
		{4, []string{"-nP", "-i4UDP", "-F0pcuPn"}},
		{6, []string{"-nP", "-i6UDP", "-F0pcuPn"}},
	} {
		output, err := fixedLsofCommand(ctx, query.arguments...)
		if err != nil {
			return ListenerInventory{}, err
		}
		parsed, err := parseLsofFieldsForFamily(output, query.family)
		clear(output)
		if err != nil {
			return ListenerInventory{}, err
		}
		records = append(records, parsed...)
	}
	seen := make(map[string]struct{})
	filtered := make([]ListenerRecord, 0, len(records))
	for _, record := range records {
		key := record.Protocol + "|" + record.BindAddress + "|" +
			strconv.Itoa(int(record.Port)) + "|" + strconv.Itoa(record.PID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		pathOutput, err := fixedReadOnlyCommand(
			ctx,
			"/bin/ps",
			"-p",
			strconv.Itoa(record.PID),
			"-o",
			"comm=",
		)
		if err != nil {
			return ListenerInventory{}, err
		}
		record.ExecutablePath = strings.TrimSpace(string(pathOutput))
		clear(pathOutput)
		if record.ExecutablePath == "" || record.ExecutablePath[0] != '/' {
			return ListenerInventory{}, ErrListenerAudit
		}
		startIdentity, liveUID, err := processStartIdentityAndUID(record.PID)
		if err != nil ||
			startIdentity == "" ||
			len(startIdentity) > 128 ||
			liveUID != record.UID {
			return ListenerInventory{}, ErrListenerAudit
		}
		record.StartIdentity = startIdentity
		record.ExecutableSHA256, err = hashRegularFile(record.ExecutablePath)
		if err != nil {
			return ListenerInventory{}, err
		}
		signatureOutput, signatureErr := fixedReadOnlyCombinedCommand(
			ctx,
			"/usr/bin/codesign",
			"-dv",
			"--verbose=4",
			record.ExecutablePath,
		)
		if signatureErr != nil {
			record.CodeSignature = "unsigned"
		} else {
			signature := compactCodeSignature(signatureOutput)
			anchorOutput, anchorErr := fixedReadOnlyCombinedCommand(
				ctx,
				"/usr/bin/codesign",
				"-v",
				"--strict",
				"-R=anchor apple",
				record.ExecutablePath,
			)
			clear(anchorOutput)
			if anchorErr == nil {
				record.CodeSignature = "apple-anchor;" + signature
			} else {
				record.CodeSignature = "non-apple-anchor;" + signature
			}
		}
		clear(signatureOutput)
		launchOutput, launchErr := fixedReadOnlyCombinedCommand(
			ctx,
			"/bin/launchctl",
			"procinfo",
			strconv.Itoa(record.PID),
		)
		if launchErr == nil {
			record.LaunchdLabel = compactLaunchdLabel(launchOutput)
		}
		clear(launchOutput)
		filtered = append(filtered, record)
	}
	sort.Slice(filtered, func(left, right int) bool {
		if filtered[left].Protocol != filtered[right].Protocol {
			return filtered[left].Protocol < filtered[right].Protocol
		}
		if filtered[left].BindAddress != filtered[right].BindAddress {
			return filtered[left].BindAddress < filtered[right].BindAddress
		}
		if filtered[left].Port != filtered[right].Port {
			return filtered[left].Port < filtered[right].Port
		}
		return filtered[left].PID < filtered[right].PID
	})
	return ListenerInventory{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().UTC().Unix(),
		Listeners:     filtered,
	}, nil
}

func EncodeListenerInventory(value ListenerInventory) ([]byte, error) {
	if value.SchemaVersion != SchemaVersion ||
		value.CollectedAt <= 0 ||
		len(value.Listeners) > 512 {
		return nil, ErrListenerAudit
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) > MaxChildControlFrame {
		return nil, ErrListenerAudit
	}
	return append(data, '\n'), nil
}

func ValidateClosedListenerInventory(
	inventory ListenerInventory,
	allowlist []ListenerAllowance,
) error {
	if inventory.SchemaVersion != SchemaVersion ||
		len(inventory.Listeners) != len(allowlist) {
		return ErrListenerAudit
	}
	used := make([]bool, len(allowlist))
	for _, record := range inventory.Listeners {
		match := -1
		for index, allowed := range allowlist {
			if used[index] {
				continue
			}
			if listenerRecordEqualsAllowance(record, allowed) {
				match = index
				break
			}
		}
		if match < 0 {
			return ErrListenerAudit
		}
		used[match] = true
	}
	return nil
}

func parseLsofFields(data []byte) ([]ListenerRecord, error) {
	return parseLsofFieldsForFamily(data, 4)
}

func parseLsofFieldsForFamily(
	data []byte,
	family int,
) ([]ListenerRecord, error) {
	if family != 4 && family != 6 {
		return nil, ErrListenerAudit
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(splitNULTerminated)
	var records []ListenerRecord
	var current ListenerRecord
	haveProcess := false
	for scanner.Scan() {
		field := strings.TrimSpace(scanner.Text())
		if len(field) < 2 {
			continue
		}
		switch field[0] {
		case 'p':
			pid, err := strconv.Atoi(field[1:])
			if err != nil || pid < 1 {
				return nil, ErrListenerAudit
			}
			current = ListenerRecord{PID: pid}
			haveProcess = true
		case 'c':
			if haveProcess {
				current.Command = field[1:]
			}
		case 'u':
			if haveProcess {
				uid, err := strconv.ParseUint(field[1:], 10, 32)
				if err != nil {
					return nil, ErrListenerAudit
				}
				current.UID = uint32(uid)
			}
		case 'P':
			if haveProcess {
				current.Protocol = strings.ToLower(field[1:])
			}
		case 'n':
			if !haveProcess || current.Protocol == "" {
				return nil, ErrListenerAudit
			}
			host, port, err := splitListenerNameForFamily(field[1:], family)
			if errors.Is(err, errConnectedSocket) {
				continue
			}
			if err != nil {
				return nil, err
			}
			record := current
			record.BindAddress = host
			record.Port = port
			records = append(records, record)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, ErrListenerAudit
	}
	return records, nil
}

func splitNULTerminated(data []byte, atEOF bool) (int, []byte, error) {
	if index := bytes.IndexByte(data, 0); index >= 0 {
		return index + 1, data[:index], nil
	}
	if atEOF && len(data) != 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func splitListenerName(value string) (string, uint16, error) {
	return splitListenerNameForFamily(value, 4)
}

func splitListenerNameForFamily(
	value string,
	family int,
) (string, uint16, error) {
	value = strings.TrimSuffix(value, " (LISTEN)")
	if strings.Contains(value, "->") {
		return "", 0, errConnectedSocket
	}
	host, portValue, err := net.SplitHostPort(value)
	if err != nil {
		index := strings.LastIndexByte(value, ':')
		if index <= 0 {
			return "", 0, ErrListenerAudit
		}
		host, portValue = value[:index], value[index+1:]
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		return "", 0, ErrListenerAudit
	}
	if host == "*" {
		host = map[int]string{4: "0.0.0.0", 6: "::"}[family]
		if host == "" {
			return "", 0, ErrListenerAudit
		}
	}
	return host, uint16(port), nil
}

func fixedLsofCommand(
	ctx context.Context,
	arguments ...string,
) ([]byte, error) {
	command := exec.CommandContext(ctx, "/usr/sbin/lsof", arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	output, err := command.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) &&
			exitError.ExitCode() == 1 &&
			len(output) == 0 {
			return []byte{}, nil
		}
		clear(output)
		return nil, ErrListenerAudit
	}
	if len(output) > 4*1024*1024 {
		clear(output)
		return nil, ErrListenerAudit
	}
	return output, nil
}

func fixedReadOnlyCommand(ctx context.Context, program string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, program, arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	output, err := command.Output()
	if err != nil || len(output) > 4*1024*1024 {
		clear(output)
		return nil, ErrListenerAudit
	}
	return output, nil
}

func fixedReadOnlyCombinedCommand(ctx context.Context, program string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, program, arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	if len(output) > 1024*1024 {
		clear(output)
		return nil, ErrListenerAudit
	}
	return output, err
}

func hashRegularFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 {
		return "", ErrListenerAudit
	}
	file, err := os.Open(path)
	if err != nil {
		return "", ErrListenerAudit
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(file, 1024*1024*1024)); err != nil {
		return "", ErrListenerAudit
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) {
		return "", ErrListenerAudit
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func compactCodeSignature(data []byte) string {
	identifier := findOutputValue(data, "Identifier=")
	team := findOutputValue(data, "TeamIdentifier=")
	authority := findOutputValue(data, "Authority=")
	if identifier == "" || authority == "" {
		return "unsigned"
	}
	return "identifier=" + identifier + ";team=" + team + ";authority=" + authority
}

func compactLaunchdLabel(data []byte) string {
	return findOutputValue(data, "label = ")
}

func findOutputValue(data []byte, prefix string) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}
