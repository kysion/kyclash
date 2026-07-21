//go:build !darwin || !kyclash_utun

package userspace

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func createTunnel(prefixes []netip.Prefix, mtu int) (tun.Device, *netstack.Net, string, error) {
	addresses := make([]netip.Addr, 0, len(prefixes))
	for _, prefix := range prefixes {
		addresses = append(addresses, prefix.Addr())
	}
	device, network, err := netstack.CreateNetTUN(addresses, nil, mtu)
	return device, network, "userspace", err
}
