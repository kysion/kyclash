//go:build darwin && kyclash_utun && (kyclash_vm_network_lab || kyclash_vm_external_peer_lab)

package vmnetworklab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"os/exec"
	"sort"
	"time"
)

type SystemSnapshot struct {
	Routes        RouteSnapshot
	DefaultRoutes []string
	DNSHash       [sha256.Size]byte
	ProxyHash     [sha256.Size]byte
}

func CaptureSystemSnapshot(inspector RouteInspector) (SystemSnapshot, error) {
	if inspector == nil {
		return SystemSnapshot{}, ErrRouteDiscovery
	}
	routes, err := inspector.Snapshot()
	if err != nil {
		return SystemSnapshot{}, err
	}
	dns, err := fixedReadOnlyCommand("/usr/sbin/scutil", "--dns")
	if err != nil {
		return SystemSnapshot{}, err
	}
	proxy, err := fixedReadOnlyCommand("/usr/sbin/scutil", "--proxy")
	if err != nil {
		return SystemSnapshot{}, err
	}
	return SystemSnapshot{
		Routes: routes, DefaultRoutes: defaultRouteFacts(routes),
		DNSHash: sha256.Sum256(dns), ProxyHash: sha256.Sum256(proxy),
	}, nil
}

func fixedReadOnlyCommand(program string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, program, arguments...)
	command.Stdin = nil
	command.Stderr = nil
	output, err := command.Output()
	if err != nil || ctx.Err() != nil || len(output) > 4*1024*1024 {
		return nil, errors.New("read-only system snapshot failed")
	}
	return output, nil
}

func defaultRouteFacts(snapshot RouteSnapshot) []string {
	values := make([]string, 0)
	for _, entry := range snapshot.all() {
		if entry.Prefix.Bits() == 0 {
			values = append(values, entry.Prefix.String()+"|"+entry.Interface+"|"+entry.Gateway)
		}
	}
	sort.Strings(values)
	return values
}

func ValidateForeignAbsence(snapshot RouteSnapshot) error {
	return ValidateForeignAbsenceWithMihomoContract(snapshot, DefaultMihomoContract())
}

// ValidateForeignAbsenceWithMihomoContract refuses to adopt any route,
// interface, controller socket, or process that predates this exact lab
// composition. The contract is fixed by the caller's compiled composition;
// it is never supplied by the App or another unprivileged client.
func ValidateForeignAbsenceWithMihomoContract(snapshot RouteSnapshot, contract MihomoContract) error {
	if !contract.valid() {
		return ErrMihomoIdentity
	}
	if _, exists := hasExactRoute(snapshot.all(), PrivatePrefix()); exists {
		return ErrRouteConflict
	}
	for _, entry := range snapshot.IPv4 {
		if entry.Prefix.Masked() == CoveringPrefix() {
			return ErrRouteConflict
		}
	}
	if hasDefaultRoute(snapshot.all(), MihomoInterface) {
		return ErrRouteConflict
	}
	if _, err := net.InterfaceByName(MihomoInterface); err == nil {
		return errors.New("fixed Mihomo interface already exists")
	}
	if info, err := os.Lstat(contract.SocketPath); err == nil {
		return errors.New("fixed Mihomo controller already exists")
	} else if !errors.Is(err, os.ErrNotExist) || info != nil {
		return errors.New("fixed Mihomo controller state is ambiguous")
	}
	if processExistsAtPath(contract.Executable) {
		return errors.New("fixed Mihomo process already exists")
	}
	return nil
}

func VerifyFinalAbsence(inspector RouteInspector, baseline SystemSnapshot, tunnelInterface string) error {
	return VerifyFinalAbsenceWithMihomoContract(inspector, baseline, tunnelInterface, DefaultMihomoContract())
}

// VerifyFinalAbsenceWithMihomoContract proves that the exact composition did
// not change global DNS/proxy/default-route state and left neither of its
// interfaces, socket, process, nor private route behind.
func VerifyFinalAbsenceWithMihomoContract(inspector RouteInspector, baseline SystemSnapshot, tunnelInterface string, contract MihomoContract) error {
	if !contract.valid() {
		return ErrMihomoIdentity
	}
	current, err := CaptureSystemSnapshot(inspector)
	if err != nil {
		return err
	}
	if !bytes.Equal(current.DNSHash[:], baseline.DNSHash[:]) || !bytes.Equal(current.ProxyHash[:], baseline.ProxyHash[:]) || !equalStrings(current.DefaultRoutes, baseline.DefaultRoutes) {
		return errors.New("DNS, default route, or system proxy snapshot changed")
	}
	if err := ValidateReleased(current.Routes); err != nil {
		return err
	}
	for _, interfaceName := range []string{tunnelInterface, MihomoInterface} {
		if interfaceName == "" {
			continue
		}
		if _, err := net.InterfaceByName(interfaceName); err == nil {
			return errors.New("owned lab interface remained")
		}
	}
	if _, err := os.Lstat(contract.SocketPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixed Mihomo controller remained")
	}
	if processExistsAtPath(contract.Executable) {
		return errors.New("fixed Mihomo process remained")
	}
	return nil
}

func processExistsAtPath(path string) bool {
	if path == "" {
		return true
	}
	output, err := exec.Command("/bin/ps", "-axo", "command=").Output()
	if err != nil {
		// Missing process discovery is ambiguous and therefore treated as a
		// possible process.
		return true
	}
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) > 0 && string(fields[0]) == path {
			return true
		}
	}
	return false
}
