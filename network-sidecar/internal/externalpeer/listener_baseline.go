package externalpeer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
)

type ListenerBaseline struct {
	SchemaVersion uint8               `json:"schema_version"`
	CollectedAt   int64               `json:"collected_at"`
	VM            SupervisorVMConfig  `json:"vm"`
	Listeners     []ListenerAllowance `json:"listeners"`
}

type PeerListenerBaseline = ListenerBaseline

func DecodeListenerBaseline(data []byte) (ListenerBaseline, error) {
	if len(data) == 0 ||
		len(data) > MaxChildControlFrame ||
		rejectDuplicateObjectKeys(data) != nil {
		return ListenerBaseline{}, ErrListenerAudit
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var baseline ListenerBaseline
	if err := decoder.Decode(&baseline); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		baseline.Validate() != nil {
		return ListenerBaseline{}, ErrListenerAudit
	}
	return baseline, nil
}

func DecodePeerListenerBaseline(data []byte) (PeerListenerBaseline, error) {
	return DecodeListenerBaseline(data)
}

func EncodeListenerBaseline(
	baseline ListenerBaseline,
) ([]byte, error) {
	if baseline.Validate() != nil {
		return nil, ErrListenerAudit
	}
	encoded, err := json.Marshal(baseline)
	if err != nil || len(encoded) > MaxChildControlFrame {
		return nil, ErrListenerAudit
	}
	return append(encoded, '\n'), nil
}

func EncodePeerListenerBaseline(
	baseline PeerListenerBaseline,
) ([]byte, error) {
	return EncodeListenerBaseline(baseline)
}

func NewListenerBaseline(
	vm SupervisorVMConfig,
	inventory ListenerInventory,
) (ListenerBaseline, error) {
	if _, err := vm.CourierFacts(); err != nil ||
		inventory.SchemaVersion != SchemaVersion ||
		inventory.CollectedAt <= 0 ||
		len(inventory.Listeners) > 512 {
		return ListenerBaseline{}, ErrListenerAudit
	}
	listeners := make([]ListenerAllowance, 0, len(inventory.Listeners))
	for _, record := range inventory.Listeners {
		if record.PID < 1 ||
			record.StartIdentity == "" ||
			len(record.StartIdentity) > 128 {
			return ListenerBaseline{}, ErrListenerAudit
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
			return ListenerBaseline{}, ErrListenerAudit
		}
		listeners = append(listeners, allowance)
	}
	sort.Slice(listeners, func(left, right int) bool {
		if listeners[left].Protocol != listeners[right].Protocol {
			return listeners[left].Protocol < listeners[right].Protocol
		}
		if listeners[left].BindAddress != listeners[right].BindAddress {
			return listeners[left].BindAddress < listeners[right].BindAddress
		}
		if listeners[left].Port != listeners[right].Port {
			return listeners[left].Port < listeners[right].Port
		}
		if listeners[left].UID != listeners[right].UID {
			return listeners[left].UID < listeners[right].UID
		}
		return listeners[left].ExecutablePath <
			listeners[right].ExecutablePath
	})
	baseline := ListenerBaseline{
		SchemaVersion: SchemaVersion,
		CollectedAt:   inventory.CollectedAt,
		VM:            vm,
		Listeners:     listeners,
	}
	if baseline.Validate() != nil {
		return ListenerBaseline{}, ErrListenerAudit
	}
	return baseline, nil
}

func (baseline ListenerBaseline) Validate() error {
	facts, err := baseline.VM.CourierFacts()
	if baseline.SchemaVersion != SchemaVersion ||
		baseline.CollectedAt <= 0 ||
		err != nil ||
		facts.Role != baseline.VM.Role ||
		facts.VMName != baseline.VM.VMName ||
		len(baseline.Listeners) > 512 {
		return ErrListenerAudit
	}
	seen := make(map[string]struct{}, len(baseline.Listeners))
	for _, listener := range baseline.Listeners {
		if validateListenerAllowance(listener) != nil {
			return ErrListenerAudit
		}
		key := listenerKey(
			listener.Protocol,
			listener.BindAddress,
			listener.Port,
		)
		if _, exists := seen[key]; exists {
			return ErrListenerAudit
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (baseline ListenerBaseline) ValidateForVM(
	expected SupervisorVMConfig,
) error {
	_, err := expected.CourierFacts()
	if baseline.Validate() != nil ||
		err != nil ||
		baseline.VM != expected {
		return ErrListenerAudit
	}
	return nil
}

func (baseline ListenerBaseline) ValidateForConfig(
	config PeerSupervisorConfig,
) error {
	if baseline.Validate() != nil ||
		config.Validate() != nil ||
		baseline.VM.Role != "peer" ||
		baseline.VM.VMName != PeerVMName ||
		baseline.VM != config.Peer {
		return ErrListenerAudit
	}
	return nil
}

func ValidateBaselineListenerInventory(
	inventory ListenerInventory,
	baseline ListenerBaseline,
) error {
	if inventory.SchemaVersion != SchemaVersion ||
		inventory.CollectedAt <= 0 ||
		baseline.Validate() != nil ||
		len(inventory.Listeners) != len(baseline.Listeners) {
		return ErrListenerAudit
	}
	return ValidateClosedListenerInventory(inventory, baseline.Listeners)
}

func AuditListenerBaseline(
	ctx context.Context,
	baseline ListenerBaseline,
) error {
	inventory, err := CollectListenerInventory(ctx)
	if err != nil {
		return err
	}
	return ValidateBaselineListenerInventory(inventory, baseline)
}

func validateListenerAllowance(value ListenerAllowance) error {
	_, err := netip.ParseAddr(value.BindAddress)
	if err != nil ||
		value.Protocol != "tcp" && value.Protocol != "udp" ||
		value.Port == 0 ||
		value.Command == "" ||
		len(value.Command) > 256 ||
		!filepath.IsAbs(value.ExecutablePath) ||
		filepath.Clean(value.ExecutablePath) != value.ExecutablePath ||
		!validSHA256(value.ExecutableSHA256) ||
		!strings.HasPrefix(
			value.CodeSignature,
			"apple-anchor;identifier=",
		) ||
		!strings.Contains(value.CodeSignature, ";authority=") ||
		len(value.CodeSignature) > 1024 ||
		value.LaunchdLabel == "" ||
		len(value.LaunchdLabel) > 512 {
		return ErrListenerAudit
	}
	for _, text := range []string{
		value.Command,
		value.ExecutablePath,
		value.CodeSignature,
		value.LaunchdLabel,
	} {
		if containsControl(text) {
			return ErrListenerAudit
		}
	}
	if value.LaunchdPID1 &&
		(value.UID != 0 ||
			value.Command != "launchd" ||
			value.ExecutablePath != "/sbin/launchd" ||
			!strings.HasPrefix(
				value.CodeSignature,
				"apple-anchor;identifier=",
			) ||
			value.LaunchdLabel == "") {
		return ErrListenerAudit
	}
	return nil
}

func ValidatePeerRuntimeListenerInventory(
	inventory ListenerInventory,
	baseline PeerListenerBaseline,
	descriptor PeerPublicDescriptor,
	child ChildIdentity,
) error {
	if inventory.SchemaVersion != SchemaVersion ||
		baseline.Validate() != nil ||
		child.Validate(descriptor.RunID) != nil ||
		descriptor.PeerEn0PrivateIPv4 != baseline.VM.IPv4 ||
		len(inventory.Listeners) != len(baseline.Listeners)+3 {
		return ErrListenerAudit
	}
	baselineUsed := make([]bool, len(baseline.Listeners))
	runtimeExpected, err := peerRuntimeListenerKeys(descriptor)
	if err != nil {
		return err
	}
	runtimeSeen := make(map[string]struct{}, len(runtimeExpected))
	for _, record := range inventory.Listeners {
		matchedBaseline := -1
		for index, allowed := range baseline.Listeners {
			if !baselineUsed[index] &&
				listenerRecordEqualsAllowance(record, allowed) {
				matchedBaseline = index
				break
			}
		}
		if matchedBaseline >= 0 {
			baselineUsed[matchedBaseline] = true
			continue
		}
		key := listenerKey(
			record.Protocol,
			record.BindAddress,
			record.Port,
		)
		if _, expected := runtimeExpected[key]; !expected ||
			record.PID != child.PID ||
			record.StartIdentity != child.StartIdentity ||
			record.UID != child.UID ||
			record.ExecutablePath != child.Path ||
			record.ExecutableSHA256 != child.SHA256 ||
			record.CodeSignature != "unsigned" ||
			record.LaunchdLabel != "" ||
			!validChildCommand(record.Command, child.Path) {
			return ErrListenerAudit
		}
		if _, duplicate := runtimeSeen[key]; duplicate {
			return ErrListenerAudit
		}
		runtimeSeen[key] = struct{}{}
	}
	for _, used := range baselineUsed {
		if !used {
			return ErrListenerAudit
		}
	}
	if len(runtimeSeen) != len(runtimeExpected) {
		return ErrListenerAudit
	}
	return nil
}

func peerRuntimeListenerKeys(
	descriptor PeerPublicDescriptor,
) (map[string]struct{}, error) {
	if len(descriptor.Endpoints) != 3 ||
		descriptor.Endpoints[0].Transport != profile.QUIC ||
		descriptor.Endpoints[1].Transport != profile.WSS ||
		descriptor.Endpoints[2].Transport != profile.TCP {
		return nil, ErrListenerAudit
	}
	result := make(map[string]struct{}, 3)
	for index, endpoint := range descriptor.Endpoints {
		parsed, err := url.Parse(endpoint.URL)
		if err != nil ||
			parsed.User != nil ||
			parsed.Fragment != "" ||
			parsed.RawQuery != "" ||
			parsed.Hostname() != descriptor.PeerEn0PrivateIPv4 {
			return nil, ErrListenerAudit
		}
		portValue, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil || portValue < uint64(MinCarrierPort) ||
			portValue > uint64(MaxCarrierPort) {
			return nil, ErrListenerAudit
		}
		protocol := "tcp"
		expectedScheme := "wss"
		expectedPath := WSSPath
		if index == 0 {
			protocol = "udp"
			expectedScheme = "https"
			expectedPath = ""
		} else if index == 2 {
			expectedScheme = "tcp"
			expectedPath = ""
		}
		if parsed.Scheme != expectedScheme ||
			parsed.Path != expectedPath {
			return nil, ErrListenerAudit
		}
		key := listenerKey(
			protocol,
			descriptor.PeerEn0PrivateIPv4,
			uint16(portValue),
		)
		result[key] = struct{}{}
	}
	return result, nil
}

func listenerKey(protocol, address string, port uint16) string {
	return protocol + "|" + address + "|" +
		strconv.Itoa(int(port))
}

func listenerRecordEqualsAllowance(
	record ListenerRecord,
	allowed ListenerAllowance,
) bool {
	processMatches := record.PID > 1 && !allowed.LaunchdPID1
	if allowed.LaunchdPID1 {
		processMatches = record.PID == 1 &&
			record.UID == 0 &&
			record.Command == "launchd" &&
			record.ExecutablePath == "/sbin/launchd" &&
			strings.HasPrefix(
				record.CodeSignature,
				"apple-anchor;identifier=",
			) &&
			record.LaunchdLabel != ""
	}
	return processMatches &&
		record.Protocol == allowed.Protocol &&
		record.BindAddress == allowed.BindAddress &&
		record.Port == allowed.Port &&
		record.UID == allowed.UID &&
		record.Command == allowed.Command &&
		record.ExecutablePath == allowed.ExecutablePath &&
		record.ExecutableSHA256 == allowed.ExecutableSHA256 &&
		record.CodeSignature == allowed.CodeSignature &&
		record.LaunchdLabel == allowed.LaunchdLabel
}

func validChildCommand(command, path string) bool {
	base := filepath.Base(path)
	return command != "" &&
		(strings.HasPrefix(base, command) || strings.HasPrefix(command, base))
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
