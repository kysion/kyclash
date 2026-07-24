// Package externalpeerhost implements the source-only, host-orchestration
// boundary for the reviewed two-VM external-peer lab.
//
// Source builds and tests do not invoke Tart, SSH, a VM, a carrier, or any
// networking API. The concrete start-lab runner can do so only when its fixed
// CLI command is deliberately executed after the separate Layer-B approval.
// It owns only dedicated host identities and exact public-artifact envelopes.
package externalpeerhost

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
)

var (
	ErrUnsafeHostCourier      = errors.New("unsafe external-peer host courier state")
	ErrInvalidHostTransaction = errors.New("invalid external-peer host courier transaction")
)

const (
	PrivateRelativeRoot                 = "target/macos-vm-lab/private/vm-external-peer-courier"
	GuestShareRelativeRoot              = "target/macos-vm-lab/guest-share"
	GuestClientOutputRelativeRoot       = "target/macos-vm-lab/guest-client-output"
	GuestPeerOutputRelativeRoot         = "target/macos-vm-lab/guest-peer-output"
	ExternalPeerBinaryBuildRelativeRoot = "target/macos-vm-lab/build/vm-external-peer-lab"
	ExternalPeerAppBuildRelativeRoot    = "target/macos-vm-lab/build/vm-external-peer-lab-app"

	PrivateKeyName = "courier-ed25519-private.bin"
	PublicKeyName  = "courier-ed25519-public.bin"

	WorkspaceDirectoryName   = "run-workspace"
	ManagementDirectoryName  = "management-ssh"
	ManagementPublicName     = "management-ssh-public"
	ManagementReviewName     = "management-host-key-review"
	ListenerApprovalName     = "listener-baseline-approval"
	ControlDirectoryName     = "control"
	ClientDirectoryName      = "client-public"
	PeerDirectoryName        = "peer-public"
	EnvelopeDirectoryName    = "signed-envelopes"
	LayerAInputsName         = "layer-a-inputs"
	LayerBPrepareInputsName  = "layer-b-prepare-inputs"
	LayerBPinInputsName      = "layer-b-pin-inputs"
	AppTreeManifestInputName = "app-tree-manifest.json"

	ClientApprovedBaselineName  = "client-approved-listener-baseline-v1.json"
	PeerApprovedBaselineName    = "peer-approved-listener-baseline-v1.json"
	BaselineApprovalWitnessName = "listener-baseline-approval-witness-v1.json"

	PeerConfigName                  = "peer-config-v1.json"
	TicketExpectationName           = "run-ticket-expectation-v1.json"
	ClientTransferManifest          = "client-transfer-manifest-v1.json"
	RunTicketEnvelopeName           = "run-ticket-envelope.bin"
	ClientEnvelopeName              = "client-to-peer-envelope.bin"
	PeerEnvelopeName                = "peer-to-client-envelope.bin"
	CancelEnvelopeName              = "cancel-envelope.bin"
	ClientManagementKeyName         = "client-management-ed25519"
	PeerManagementKeyName           = "peer-management-ed25519"
	ClientManagementPublicName      = "client-management-ed25519-public.bin"
	PeerManagementPublicName        = "peer-management-ed25519-public.bin"
	ClientKnownHostsName            = "client-known-hosts"
	PeerKnownHostsName              = "peer-known-hosts"
	ClientHostPublicReviewName      = "client-management-ssh-host-ed25519-public.bin"
	PeerHostPublicReviewName        = "peer-management-ssh-host-ed25519-public.bin"
	ClientHostFingerprintName       = "client-management-ssh-host-ed25519-fingerprint.txt"
	PeerHostFingerprintName         = "peer-management-ssh-host-ed25519-fingerprint.txt"
	ClientSSHBootstrapWitnessName   = "client-management-ssh-bootstrap-witness-v1.json"
	PeerSSHBootstrapWitnessName     = "peer-management-ssh-bootstrap-witness-v1.json"
	keyInitializationLock           = "key-init.lock"
	managementKeyInitializationLock = "management-key-init.lock"
	transactionSigningLock          = "sign-transaction.lock"
	secureDirectoryMode             = 0o700
	secureFileMode                  = 0o600
	maximumHostArtifactBytes        = 256 * 1024
)

// Layout contains only paths derived from the checked-in command's current
// repository root. The command accepts no path argument and reads no path
// from the environment.
type Layout struct {
	RepositoryRoot    string
	PrivateRoot       string
	Workspace         string
	Management        string
	ManagementPublic  string
	ManagementReview  string
	ListenerApproval  string
	Control           string
	ClientPublic      string
	PeerPublic        string
	Envelopes         string
	GuestShare        string
	GuestClientOutput string
	GuestPeerOutput   string
	BinaryBuildRoot   string
	AppBuildRoot      string
}

func FixedLayout(repositoryRoot string) (Layout, error) {
	if !filepath.IsAbs(repositoryRoot) ||
		filepath.Clean(repositoryRoot) != repositoryRoot {
		return Layout{}, ErrUnsafeHostCourier
	}
	module, err := os.Open(filepath.Join(repositoryRoot, "network-sidecar", "go.mod"))
	if err != nil {
		return Layout{}, ErrUnsafeHostCourier
	}
	moduleBytes, readErr := io.ReadAll(io.LimitReader(module, 4097))
	closeErr := module.Close()
	if readErr != nil || closeErr != nil || len(moduleBytes) > 4096 ||
		!bytes.HasPrefix(
			moduleBytes,
			[]byte("module github.com/kysion/kyclash/network-sidecar\n"),
		) {
		clear(moduleBytes)
		return Layout{}, ErrUnsafeHostCourier
	}
	clear(moduleBytes)
	privateRoot := filepath.Join(repositoryRoot, filepath.FromSlash(PrivateRelativeRoot))
	workspace := filepath.Join(privateRoot, WorkspaceDirectoryName)
	return Layout{
		RepositoryRoot:   repositoryRoot,
		PrivateRoot:      privateRoot,
		Workspace:        workspace,
		Management:       filepath.Join(privateRoot, ManagementDirectoryName),
		ManagementPublic: filepath.Join(privateRoot, ManagementPublicName),
		ManagementReview: filepath.Join(privateRoot, ManagementReviewName),
		ListenerApproval: filepath.Join(privateRoot, ListenerApprovalName),
		Control:          filepath.Join(workspace, ControlDirectoryName),
		ClientPublic:     filepath.Join(workspace, ClientDirectoryName),
		PeerPublic:       filepath.Join(workspace, PeerDirectoryName),
		Envelopes:        filepath.Join(workspace, EnvelopeDirectoryName),
		GuestShare: filepath.Join(
			repositoryRoot,
			filepath.FromSlash(GuestShareRelativeRoot),
		),
		GuestClientOutput: filepath.Join(
			repositoryRoot,
			filepath.FromSlash(GuestClientOutputRelativeRoot),
		),
		GuestPeerOutput: filepath.Join(
			repositoryRoot,
			filepath.FromSlash(GuestPeerOutputRelativeRoot),
		),
		BinaryBuildRoot: filepath.Join(
			repositoryRoot,
			filepath.FromSlash(ExternalPeerBinaryBuildRelativeRoot),
		),
		AppBuildRoot: filepath.Join(
			repositoryRoot,
			filepath.FromSlash(ExternalPeerAppBuildRelativeRoot),
		),
	}, nil
}

var (
	controlInputNames = []string{
		PeerConfigName,
		TicketExpectationName,
	}
	clientInputNames = []string{
		"client-public-v1.json",
		"tls-client.csr.der",
		"overlay-ssh-client-ed25519-public.bin",
		ClientTransferManifest,
	}
	peerInputNames = []string{
		"peer-public-v1.json",
		"tls-ca.der",
		"tls-server.der",
		"tls-client.der",
		"overlay-ssh-server-ed25519-public.bin",
		"system-sshd-ed25519-public.bin",
		"transfer-manifest-v1.json",
	}
	signedEnvelopeNames = []string{
		RunTicketEnvelopeName,
		ClientEnvelopeName,
	}
	successEnvelopeNames = []string{
		RunTicketEnvelopeName,
		ClientEnvelopeName,
		PeerEnvelopeName,
	}
	cancelEnvelopeNames = []string{
		RunTicketEnvelopeName,
		ClientEnvelopeName,
		CancelEnvelopeName,
	}
	successCancelEnvelopeNames = []string{
		RunTicketEnvelopeName,
		ClientEnvelopeName,
		PeerEnvelopeName,
		CancelEnvelopeName,
	}
	managementNames = []string{
		ClientManagementKeyName,
		PeerManagementKeyName,
		ClientKnownHostsName,
		PeerKnownHostsName,
	}
	managementPrivateNames = []string{
		ClientManagementKeyName,
		PeerManagementKeyName,
	}
	managementPublicNames = []string{
		ClientManagementPublicName,
		PeerManagementPublicName,
	}
	managementReviewNames = []string{
		ClientHostPublicReviewName,
		ClientHostFingerprintName,
		ClientSSHBootstrapWitnessName,
		PeerHostPublicReviewName,
		PeerHostFingerprintName,
		PeerSSHBootstrapWitnessName,
	}
)
