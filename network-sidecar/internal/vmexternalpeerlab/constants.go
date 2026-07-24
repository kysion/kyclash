// Package vmexternalpeerlab contains the sealed client-side contract for the
// two-VirtualMac external-peer lab. It is intentionally separate from the
// existing loopback VM-network lab and from production composition.
package vmexternalpeerlab

import "net/netip"

const (
	SocketPath          = "/var/run/net.kysion.kyclash.vm-external-peer-lab.sock"
	StageRoot           = "/private/var/tmp/kyclash-vm-external-peer-lab-stage"
	StateRoot           = "/private/var/tmp/kyclash-vm-external-peer-lab-root"
	JournalPath         = StateRoot + "/route-lease-v1.json"
	MihomoSocket        = StateRoot + "/mihomo.sock"
	SupervisorPath      = StageRoot + "/kyclash-vm-external-peer-lab-supervisor"
	HarnessPath         = StageRoot + "/kyclash-vm-external-peer-lab-harness"
	MihomoPath          = StageRoot + "/mihomo"
	MihomoConfig        = StageRoot + "/mihomo-config.json"
	AppManifestPath     = StageRoot + "/app-manifest-v1.json"
	AppTreeManifestPath = StageRoot + "/app-tree-manifest.json"
	AppBundlePath       = "/Applications/KyClash.app"
	AppExecutablePath   = "/Applications/KyClash.app/Contents/MacOS/clash-verge"
	CourierPublicKey    = StageRoot + "/courier-ed25519-public.bin"
	ClientOutboxRoot    = StateRoot + "/client-public-outbox"
	ClientInboxRoot     = StateRoot + "/peer-public-inbox"
	ClientManifestName  = "client-transfer-manifest-v1.json"
	ClientReadyName     = "client-public-ready-v1"
	PeerReadyName       = "peer-public-ready-v1"
	RunTicketName       = "run-ticket-v1.bin"
	ClientEnvelopeName  = "client-to-peer-envelope-v1.bin"
	PeerEnvelopeName    = "peer-to-client-envelope-v1.bin"
	ProfileID           = "lab.vm-external-peer.actual-child"
	SiteID              = "lab-vm-external-peer"
	RuntimeMode         = "vm_external_peer_lab"
	TunnelKind          = "darwin_utun"
	MihomoInterface     = "utun4094"
	CoveringCIDR        = "10.88.0.0/24"
	PrivateCIDR         = "10.88.0.2/32"
	PrivateEcho         = "10.88.0.2:8080"
	OverlaySSH          = "10.88.0.2:22"
	SystemSSH           = "10.88.0.2:2222"
	ClientCIDR          = "10.88.0.1/32"
	EchoPayload         = "kyclash-vm-external-peer-echo-v1"
	RunnerEnv           = "local-virtualization-framework"
	VMConfirmation      = "authorized-kyclash-virtualization-framework-vm"
	RuntimeTarget       = "kyclash-macos-lab-work"
	PeerRuntimeTarget   = "kyclash-macos-lab-peer"
	StartupSeconds      = 120
	MihomoConfigSHA256  = "ff45607149b2afd7bc704cde7fbf4814382cf93b42a960f4760ff9850b09b3a3"
)

var (
	privatePrefix = netip.MustParsePrefix(PrivateCIDR)
	coverPrefix   = netip.MustParsePrefix(CoveringCIDR)
	clientPrefix  = netip.MustParsePrefix(ClientCIDR)
)

func PrivatePrefix() netip.Prefix  { return privatePrefix }
func CoveringPrefix() netip.Prefix { return coverPrefix }
func ClientPrefix() netip.Prefix   { return clientPrefix }
