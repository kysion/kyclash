package vmnetworklab

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

var (
	ErrRouteDiscovery = errors.New("route discovery failed")
	ErrRouteConflict  = errors.New("fixed private route conflict")
	ErrRouteAmbiguous = errors.New("route absence is ambiguous")
)

type RouteEntry struct {
	Prefix    netip.Prefix
	Interface string
	Gateway   string
}

func (entry RouteEntry) normalized() RouteEntry {
	entry.Prefix = entry.Prefix.Masked()
	return entry
}

func validUTUN(value string) bool {
	if len(value) < 5 || !strings.HasPrefix(value, "utun") {
		return false
	}
	suffix := value[4:]
	if suffix == "" || (len(suffix) > 1 && suffix[0] == '0') {
		return false
	}
	for _, character := range suffix {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func parseIPv4Destination(value string, flags string) (netip.Prefix, error) {
	if value == "default" {
		return netip.MustParsePrefix("0.0.0.0/0"), nil
	}
	parts := strings.SplitN(value, "/", 2)
	addressParts := strings.Split(parts[0], ".")
	if len(addressParts) == 0 || len(addressParts) > 4 {
		return netip.Prefix{}, ErrRouteDiscovery
	}
	octets := make([]string, 4)
	for index := range octets {
		octets[index] = "0"
	}
	for index, part := range addressParts {
		if part == "" {
			return netip.Prefix{}, ErrRouteDiscovery
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 || value > 255 {
			return netip.Prefix{}, ErrRouteDiscovery
		}
		octets[index] = strconv.Itoa(value)
	}
	prefix := len(addressParts) * 8
	if strings.Contains(flags, "H") {
		prefix = 32
	}
	if len(parts) == 2 {
		parsed, err := strconv.Atoi(parts[1])
		if err != nil || parsed < 0 || parsed > 32 {
			return netip.Prefix{}, ErrRouteDiscovery
		}
		prefix = parsed
	}
	address, err := netip.ParseAddr(strings.Join(octets, "."))
	if err != nil {
		return netip.Prefix{}, ErrRouteDiscovery
	}
	return netip.PrefixFrom(address, prefix).Masked(), nil
}

func parseIPv6Destination(value string, flags string) (netip.Prefix, error) {
	if value == "default" {
		return netip.MustParsePrefix("::/0"), nil
	}
	parts := strings.SplitN(value, "/", 2)
	addressText := strings.SplitN(parts[0], "%", 2)[0]
	address, err := netip.ParseAddr(addressText)
	if err != nil || !address.Is6() {
		return netip.Prefix{}, ErrRouteDiscovery
	}
	prefix := 128
	if len(parts) == 2 {
		prefix, err = strconv.Atoi(parts[1])
		if err != nil || prefix < 0 || prefix > 128 {
			return netip.Prefix{}, ErrRouteDiscovery
		}
	} else if !strings.Contains(flags, "H") {
		prefix = 128
	}
	return netip.PrefixFrom(address, prefix).Masked(), nil
}

// ParseNetstat accepts the stable destination/gateway/flags/netif columns
// emitted by macOS `netstat -rn -f inet[6]`. It intentionally rejects
// malformed rows instead of silently treating an unknown route as absent.
func ParseNetstat(output string, ipv6 bool) ([]RouteEntry, error) {
	foundHeader := false
	entries := make([]RouteEntry, 0)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Destination" {
			foundHeader = true
			continue
		}
		if !foundHeader {
			continue
		}
		if len(fields) < 4 {
			return nil, ErrRouteDiscovery
		}
		var prefix netip.Prefix
		var err error
		if ipv6 {
			prefix, err = parseIPv6Destination(fields[0], fields[2])
		} else {
			prefix, err = parseIPv4Destination(fields[0], fields[2])
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, RouteEntry{Prefix: prefix, Interface: fields[3], Gateway: fields[1]}.normalized())
	}
	if !foundHeader {
		return nil, ErrRouteDiscovery
	}
	return entries, nil
}

func hasDefaultRoute(entries []RouteEntry, interfaces ...string) bool {
	for _, entry := range entries {
		if entry.Prefix.Bits() != 0 {
			continue
		}
		for _, interfaceName := range interfaces {
			if entry.Interface == interfaceName {
				return true
			}
		}
	}
	return false
}

func hasExactRoute(entries []RouteEntry, prefix netip.Prefix) (RouteEntry, bool) {
	prefix = prefix.Masked()
	for _, entry := range entries {
		entry = entry.normalized()
		if entry.Prefix == prefix {
			return entry, true
		}
	}
	return RouteEntry{}, false
}

type RouteSnapshot struct {
	IPv4 []RouteEntry
	IPv6 []RouteEntry
}

func (snapshot RouteSnapshot) all() []RouteEntry {
	entries := make([]RouteEntry, 0, len(snapshot.IPv4)+len(snapshot.IPv6))
	entries = append(entries, snapshot.IPv4...)
	entries = append(entries, snapshot.IPv6...)
	return entries
}

type RouteInspector interface {
	Snapshot() (RouteSnapshot, error)
}

type RouteExecutor interface {
	Add(interfaceName string) error
	Delete(interfaceName string) error
}

// ValidatePreflight proves that the fixed Mihomo route is the sole permitted
// covering route and that no exact private target route is already present.
func ValidatePreflight(snapshot RouteSnapshot) error {
	all := snapshot.all()
	if hasDefaultRoute(all, MihomoInterface) {
		return fmt.Errorf("%w: default route on Mihomo interface", ErrRouteConflict)
	}
	if entry, ok := hasExactRoute(all, PrivatePrefix()); ok {
		return fmt.Errorf("%w: exact route already exists on %s", ErrRouteConflict, entry.Interface)
	}
	coverCount := 0
	for _, entry := range snapshot.IPv4 {
		entry = entry.normalized()
		if entry.Prefix == CoveringPrefix() && entry.Interface == MihomoInterface {
			coverCount++
		}
	}
	if coverCount != 1 {
		return fmt.Errorf("%w: expected one Mihomo covering route", ErrRouteConflict)
	}
	return nil
}

func ValidateApplied(snapshot RouteSnapshot, interfaceName string) error {
	if !validUTUN(interfaceName) {
		return ErrRouteConflict
	}
	if entry, ok := hasExactRoute(snapshot.all(), PrivatePrefix()); !ok || entry.Interface != interfaceName {
		return fmt.Errorf("%w: exact route is not owned by %s", ErrRouteConflict, interfaceName)
	}
	return ValidatePreflightWithoutExact(snapshot)
}

func ValidatePreflightWithoutExact(snapshot RouteSnapshot) error {
	all := snapshot.all()
	if hasDefaultRoute(all, MihomoInterface) {
		return fmt.Errorf("%w: default route on Mihomo interface", ErrRouteConflict)
	}
	coverCount := 0
	for _, entry := range snapshot.IPv4 {
		entry = entry.normalized()
		if entry.Prefix == CoveringPrefix() && entry.Interface == MihomoInterface {
			coverCount++
		}
	}
	if coverCount != 1 {
		return fmt.Errorf("%w: Mihomo covering route changed", ErrRouteConflict)
	}
	return nil
}

func ValidateReleased(snapshot RouteSnapshot) error {
	all := snapshot.all()
	if _, ok := hasExactRoute(all, PrivatePrefix()); ok {
		return ErrRouteAmbiguous
	}
	for _, entry := range snapshot.IPv4 {
		if entry.normalized().Prefix == CoveringPrefix() && entry.Interface == MihomoInterface {
			return fmt.Errorf("%w: Mihomo covering route still present", ErrRouteAmbiguous)
		}
	}
	return nil
}
