// Package externalpeer contains the public-artifact protocol and the
// unprivileged peer runtime for the reviewed two-VM KyClash lab.
//
// It is deliberately separate from systemlabpeer. The latter is a loopback
// fixture; this package rejects loopback and wildcard underlay endpoints and
// requires a run-bound mutual-TLS identity before a carrier can reach the
// WireGuard switchboard.
package externalpeer

import "time"

const (
	SchemaVersion uint8 = 1

	ProfileID   = "lab.vm-external-peer.actual-child"
	SiteID      = "lab-vm-external-peer"
	RuntimeMode = "vm_external_peer_lab"
	TunnelKind  = "darwin_utun"

	ClientVMName  = "kyclash-macos-lab-work"
	PeerVMName    = "kyclash-macos-lab-peer"
	BindInterface = "en0"

	InnerClientIPv4        = "10.88.0.1"
	InnerPeerIPv4          = "10.88.0.2"
	PrivateRoute           = "10.88.0.2/32"
	MihomoDevice           = "utun4094"
	MihomoRoute            = "10.88.0.0/24"
	PrivateEchoPort uint16 = 8080
	OverlaySSHPort  uint16 = 22
	SystemSSHPort   uint16 = 2222

	WSSPath  = "/kynp"
	QUICALPN = "kyclash-network/1"

	MinCarrierPort uint16 = 20_000
	MaxCarrierPort uint16 = 60_000

	RootStateDir                  = "/private/var/tmp/kyclash-vm-external-peer-lab-root"
	PeerStagingManifestPath       = "/private/etc/net.kysion.kyclash.vm-external-peer-lab/peer-staging-manifest.json"
	PeerFixedConfigPath           = "/private/etc/net.kysion.kyclash.vm-external-peer-lab/peer-config-v1.json"
	PeerRunTicketExpectationPath  = "/private/etc/net.kysion.kyclash.vm-external-peer-lab/run-ticket-expectation-v1.json"
	ClientListenerBaselinePath    = "/private/etc/net.kysion.kyclash.vm-external-peer-lab/client-listener-baseline-v1.json"
	PeerListenerBaselinePath      = "/private/etc/net.kysion.kyclash.vm-external-peer-lab/peer-listener-baseline-v1.json"
	PeerJournalPath               = "/private/var/db/net.kysion.kyclash.vm-external-peer-lab/peer-journal.json"
	PeerAuthorizedKeysWitnessPath = "/private/var/db/net.kysion.kyclash.vm-external-peer-lab/authorized-keys-witness.bin"
	PeerAuthorizedKeysScratchPath = "/private/var/db/net.kysion.kyclash.vm-external-peer-lab/authorized-keys-witness.pending"
	PeerControlSocket             = "/private/var/run/net.kysion.kyclash.vm-external-peer-lab.peer-control.sock"
	PeerRunNoncePath              = "/private/var/run/net.kysion.kyclash.vm-external-peer-lab.run-nonce"
	PeerCourierInbox              = RootStateDir + "/peer-courier-inbox"
	PeerPublicOutbox              = RootStateDir + "/peer-public-outbox"
	PeerPublicStatus              = RootStateDir + "/peer-status-v1.json"
	PeerWakeTrigger               = PeerCourierInbox + "/wake"
	PeerCancelTrigger             = PeerCourierInbox + "/cancel-wake"
	PeerRunTicketEnvelope         = PeerCourierInbox + "/run-ticket-envelope.bin"
	PeerClientEnvelope            = PeerCourierInbox + "/client-to-peer-envelope.bin"
	PeerCancelEnvelope            = PeerCourierInbox + "/cancel-envelope.bin"
	PeerClientTransferManifest    = PeerCourierInbox + "/client-transfer-manifest-v1.json"

	ForcedCommandName            = "kyclash-read-run-nonce-v1"
	OverlaySSHProofACKName       = "kyclash-proof-ack-v1"
	OverlaySSHProofACKDomain     = "net.kysion.kyclash.overlay-ssh-proof-ack/v1\x00"
	PeerSupervisorPath           = "/Library/PrivilegedHelperTools/net.kysion.kyclash.vm-external-peer-lab.peer-supervisor"
	PeerChildPath                = "/usr/local/libexec/kyclash-vm-external-peer-lab-peer"
	ListenerAuditorPath          = "/usr/local/libexec/kyclash-vm-external-peer-lab-listener-auditor"
	ForcedCommandHelperPath      = "/usr/local/libexec/kyclash-vm-external-peer-lab-forced-command"
	RestrictedAuthorizedKeysPath = "/Users/kyclashlabssh/.ssh/authorized_keys"
	SystemSSHHostPublicKeyPath   = "/etc/ssh/ssh_host_ed25519_key.pub"

	CourierDomain = "net.kysion.kyclash.external-peer.courier/v1\x00"

	MaxDescriptorSize = 16 * 1024
	MaxArtifactSize   = 64 * 1024
	MaxRunLifetime    = 2 * time.Hour
	MinRemainingLife  = 10 * time.Minute
	MaxCourierLife    = 120 * time.Second
)

var (
	ClientArtifactNames = [...]string{
		"client-public-v1.json",
		"tls-client.csr.der",
		"overlay-ssh-client-ed25519-public.bin",
	}
	PeerArtifactNames = [...]string{
		"peer-public-v1.json",
		"tls-ca.der",
		"tls-server.der",
		"tls-client.der",
		"overlay-ssh-server-ed25519-public.bin",
		"system-sshd-ed25519-public.bin",
		"transfer-manifest-v1.json",
	}
	PeerInboxRunNames = [...]string{
		"run-ticket-envelope.bin",
		"client-public-v1.json",
		"tls-client.csr.der",
		"overlay-ssh-client-ed25519-public.bin",
		"client-transfer-manifest-v1.json",
		"client-to-peer-envelope.bin",
		"wake",
	}
)
