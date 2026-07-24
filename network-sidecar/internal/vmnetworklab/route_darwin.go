//go:build darwin && kyclash_utun && (kyclash_vm_network_lab || kyclash_vm_external_peer_lab)

package vmnetworklab

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

type DarwinRouteInspector struct{}

func (DarwinRouteInspector) Snapshot() (RouteSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), routeCommandTimeout)
	defer cancel()
	ipv4, err := runRouteReadOnly(ctx, "inet")
	if err != nil {
		return RouteSnapshot{}, err
	}
	ipv6, err := runRouteReadOnly(ctx, "inet6")
	if err != nil {
		return RouteSnapshot{}, err
	}
	return RouteSnapshot{IPv4: ipv4, IPv6: ipv6}, nil
}

func runRouteReadOnly(ctx context.Context, family string) ([]RouteEntry, error) {
	if family != "inet" && family != "inet6" {
		return nil, ErrRouteDiscovery
	}
	command := exec.CommandContext(ctx, "/usr/sbin/netstat", "-rn", "-f", family)
	command.Stdin = nil
	command.Stderr = nil
	output, err := command.Output()
	if err != nil || ctx.Err() != nil {
		return nil, ErrRouteDiscovery
	}
	return ParseNetstat(string(output), family == "inet6")
}

type DarwinRouteExecutor struct{}

func (DarwinRouteExecutor) Add(interfaceName string) error {
	return executeFixedRoute("add", interfaceName)
}

func (DarwinRouteExecutor) Delete(interfaceName string) error {
	return executeFixedRoute("delete", interfaceName)
}

func executeFixedRoute(action, interfaceName string) error {
	if action != "add" && action != "delete" || !validUTUN(interfaceName) {
		return ErrRouteConflict
	}
	command := exec.Command("/sbin/route", "-n", action, "-net", PrivateCIDR, "-interface", interfaceName)
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Run(); err != nil {
		return errors.New("fixed private route mutation failed")
	}
	return nil
}

const routeCommandTimeout = 3e9 // 3 seconds; avoids importing time in constants-only paths.

func routeInterfaceFromOutput(output string) string {
	return strings.TrimSpace(output)
}
