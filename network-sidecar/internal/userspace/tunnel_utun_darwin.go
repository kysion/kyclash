//go:build darwin && kyclash_utun

package userspace

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"strconv"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func createTunnel(prefixes []netip.Prefix, mtu int) (tun.Device, *netstack.Net, string, error) {
	if len(prefixes) == 0 || mtu != 1420 {
		return nil, nil, "", ErrInvalidState
	}
	device, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, nil, "", err
	}
	name, err := device.Name()
	if err != nil || !validUTUNName(name) {
		_ = device.Close()
		return nil, nil, "", errors.New("created device returned invalid utun name")
	}
	if err := configureLocalAddresses(context.Background(), name, prefixes, mtu); err != nil {
		_ = device.Close()
		return nil, nil, "", err
	}
	return device, nil, name, nil
}

func configureLocalAddresses(ctx context.Context, name string, prefixes []netip.Prefix, mtu int) error {
	if !validUTUNName(name) || mtu != 1420 || len(prefixes) == 0 {
		return ErrInvalidState
	}
	for _, prefix := range prefixes {
		if !prefix.IsValid() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return ErrInvalidState
		}
		address := prefix.Addr().String()
		var arguments []string
		if prefix.Addr().Is4() {
			mask := net.CIDRMask(prefix.Bits(), 32)
			arguments = []string{name, "inet", address, address, "netmask", net.IP(mask).String(), "alias"}
		} else {
			arguments = []string{name, "inet6", address, "prefixlen", strconv.Itoa(prefix.Bits()), "alias"}
		}
		if output, err := exec.CommandContext(ctx, "/sbin/ifconfig", arguments...).CombinedOutput(); err != nil {
			clear(output)
			return errors.New("configure utun local address")
		}
	}
	output, err := exec.CommandContext(ctx, "/sbin/ifconfig", name, "mtu", strconv.Itoa(mtu), "up").CombinedOutput()
	clear(output)
	if err != nil {
		return errors.New("activate configured utun")
	}
	return nil
}
