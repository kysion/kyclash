// Package vmnetworklab contains the fixed, disposable-VM-only core-network
// lab.  It is deliberately independent from the production route helper and
// tunnel broker; callers cannot provide paths, routes, endpoints, or command
// arguments.
package vmnetworklab

import "net/netip"

const (
	SocketPath      = "/var/run/net.kysion.kyclash.vm-network-lab.sock"
	StageRoot       = "/private/var/tmp/kyclash-vm-network-lab-stage"
	StateRoot       = "/private/var/tmp/kyclash-vm-network-lab-root"
	JournalPath     = StateRoot + "/route-lease-v1.json"
	MihomoSocket    = StateRoot + "/mihomo.sock"
	HarnessPath     = StageRoot + "/kyclash-vm-network-lab-harness"
	MihomoPath      = StageRoot + "/mihomo"
	MihomoConfig    = StageRoot + "/mihomo-config.json"
	ProfileID       = "lab.vm-network.actual-child"
	SiteID          = "lab-vm-network"
	RuntimeMode     = "vm_network_lab"
	TunnelKind      = "darwin_utun"
	MihomoInterface = "utun4094"
	CoveringCIDR    = "10.88.0.0/24"
	PrivateCIDR     = "10.88.0.2/32"
	PrivateEcho     = "10.88.0.2:8080"
	ClientCIDR      = "10.88.0.1/32"
	EchoPayload     = "kyclash-vm-network-echo-v1"
	RunnerEnv       = "local-virtualization-framework"
	VMConfirmation  = "authorized-kyclash-virtualization-framework-vm"
	RuntimeTarget   = "kyclash-macos-lab-work"
	ConfigSHA256    = "2ad62e399c953f5298d8de22ee7d762277968f18e186c97d281cfdb67b10df5d"
)

var (
	privatePrefix = netip.MustParsePrefix(PrivateCIDR)
	coverPrefix   = netip.MustParsePrefix(CoveringCIDR)
	clientPrefix  = netip.MustParsePrefix(ClientCIDR)
)

func PrivatePrefix() netip.Prefix  { return privatePrefix }
func CoveringPrefix() netip.Prefix { return coverPrefix }
func ClientPrefix() netip.Prefix   { return clientPrefix }
