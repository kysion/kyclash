// Package externalpeergueststaging implements the create-only, visibly
// authorized guest staging boundary for the locked two-VirtualMac
// external-peer lab.
//
// It never starts the App, either supervisor, a carrier, Mihomo, a tunnel, or
// a route. Layer A installs immutable bytes and records a listener inventory.
// Layer B first emits a baseline candidate for human review and only a
// separate pin phase can create the runtime manifests.
package externalpeergueststaging

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
)

type Role string

const (
	ClientRole Role = "client"
	PeerRole   Role = "peer"
)

type Phase string

const (
	LayerAStage           Phase = "layer-a-stage"
	LayerASSHBootstrap    Phase = "layer-a-ssh-bootstrap"
	LayerBPrepare         Phase = "layer-b-prepare"
	LayerBPin             Phase = "layer-b-pin"
	inputDirectoryMode          = 0o700
	inputFileMode               = 0o600
	inputExecutableMode         = 0o500
	reviewDirectoryMode         = 0o755
	reviewFileMode              = 0o444
	rootPrivateMode             = 0o600
	rootPublicKeyMode           = 0o400
	rootExecutableMode          = 0o755
	rootPrivateExecMode         = 0o500
	maximumExecutableSize       = 512 * 1024 * 1024
	maximumAppFileSize          = 512 * 1024 * 1024
	maximumAppTreeSize          = 2 * 1024 * 1024 * 1024
	maximumAppEntries           = 4096
	maximumAppDepth             = 16
)

const (
	InputBase = "/private/var/tmp/kyclash-vm-external-peer-lab-staging-input"

	ClientLayerAInput        = InputBase + "/client-layer-a"
	ClientSSHBootstrapInput  = InputBase + "/client-ssh-bootstrap-layer-a"
	ClientLayerBPrepareInput = InputBase + "/client-layer-b-prepare"
	ClientLayerBPinInput     = InputBase + "/client-layer-b-pin"
	PeerLayerAInput          = InputBase + "/peer-layer-a"
	PeerSSHBootstrapInput    = InputBase + "/peer-ssh-bootstrap-layer-a"
	PeerLayerBPrepareInput   = InputBase + "/peer-layer-b-prepare"
	PeerLayerBPinInput       = InputBase + "/peer-layer-b-pin"

	ClientReviewRoot = "/private/var/tmp/kyclash-vm-external-peer-lab-client-review"
	PeerReviewRoot   = "/private/var/tmp/kyclash-vm-external-peer-lab-peer-review"

	ListenerInventoryName   = "listener-inventory-v1.json"
	BaselineCandidateName   = "listener-baseline-candidate-v1.json"
	ReviewWitnessName       = "layer-b-review-witness-v1.json"
	SSHBootstrapWitnessName = "management-ssh-bootstrap-witness-v1.json"
	SSHHostPublicKeyName    = "management-ssh-host-ed25519-public.bin"
	SSHHostFingerprintName  = "management-ssh-host-ed25519-fingerprint.txt"
	VMIdentityWitnessName   = "vm-identity-layer-a-v1.json"

	AppInputName                  = "KyClash.app"
	MihomoInputName               = "mihomo"
	MihomoConfigInputName         = "mihomo-config.json"
	PeerConfigInputName           = "peer-config-v1.json"
	TicketExpectationInputName    = "run-ticket-expectation-v1.json"
	CourierPublicKeyInputName     = "courier-ed25519-public.bin"
	ApprovedListenerBaselineName  = "approved-listener-baseline-v1.json"
	ClientManagementPublicKeyName = "client-management-ed25519-public.bin"
	PeerManagementPublicKeyName   = "peer-management-ed25519-public.bin"
)

var ErrGuestStaging = errors.New("external-peer guest staging refused")

type Layout struct {
	InputBase       string
	ClientReview    string
	PeerReview      string
	ClientStageRoot string
	Applications    string
	Configuration   string
	PeerSupervisor  string
	PeerChild       string
	ListenerAuditor string
	ForcedCommand   string
	TransactionRoot string
}

func ProductionLayout() Layout {
	return Layout{
		InputBase:       InputBase,
		ClientReview:    ClientReviewRoot,
		PeerReview:      PeerReviewRoot,
		ClientStageRoot: vmexternalpeerlab.StageRoot,
		Applications:    "/Applications",
		Configuration:   filepath.Dir(externalpeer.PeerFixedConfigPath),
		PeerSupervisor:  externalpeer.PeerSupervisorPath,
		PeerChild:       externalpeer.PeerChildPath,
		ListenerAuditor: externalpeer.ListenerAuditorPath,
		ForcedCommand:   externalpeer.ForcedCommandHelperPath,
		TransactionRoot: "/private/var/db/" +
			"net.kysion.kyclash.vm-external-peer-lab-guest-staging",
	}
}

type RuntimeFacts struct {
	GOOS          string
	GOARCH        string
	EffectiveUID  int
	ConsoleUID    uint32
	ConsoleGID    uint32
	Model         string
	Runner        string
	Confirmation  string
	RuntimeTarget string
	Executable    string
	Identity      VMIdentity
}

func ValidateRuntimeFacts(role Role, facts RuntimeFacts) error {
	target := vmexternalpeerlab.RuntimeTarget
	if role == PeerRole {
		target = vmexternalpeerlab.PeerRuntimeTarget
	}
	if role != ClientRole && role != PeerRole ||
		facts.GOOS != "darwin" ||
		facts.GOARCH != "arm64" ||
		facts.EffectiveUID != 0 ||
		facts.ConsoleUID == 0 ||
		facts.Model == "" ||
		!strings.HasPrefix(strings.TrimSpace(facts.Model), "VirtualMac") ||
		facts.Identity.Validate() != nil ||
		facts.Identity.Model != facts.Model ||
		facts.Runner != vmexternalpeerlab.RunnerEnv ||
		facts.Confirmation != vmexternalpeerlab.VMConfirmation ||
		facts.RuntimeTarget != target ||
		!filepath.IsAbs(facts.Executable) ||
		filepath.Clean(facts.Executable) != facts.Executable {
		return ErrGuestStaging
	}
	return nil
}

func productionRuntimeFacts() (RuntimeFacts, error) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return RuntimeFacts{}, ErrGuestStaging
	}
	console, err := os.Stat("/dev/console")
	if err != nil {
		return RuntimeFacts{}, ErrGuestStaging
	}
	identity, err := identityFromInfo(console)
	if err != nil || identity.UID == 0 {
		return RuntimeFacts{}, ErrGuestStaging
	}
	executable, err := os.Executable()
	if err != nil {
		return RuntimeFacts{}, ErrGuestStaging
	}
	identityFacts, err := collectProductionVMIdentity(nil)
	if err != nil {
		return RuntimeFacts{}, ErrGuestStaging
	}
	return RuntimeFacts{
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		EffectiveUID: os.Geteuid(),
		ConsoleUID:   identity.UID, ConsoleGID: identity.GID,
		Model:         identityFacts.Model,
		Runner:        os.Getenv("KYCLASH_RUNNER_ENVIRONMENT"),
		Confirmation:  os.Getenv("KYCLASH_VM_LAB_CONFIRM"),
		RuntimeTarget: os.Getenv("KYCLASH_RUNTIME_TARGET"),
		Executable:    executable,
		Identity:      identityFacts,
	}, nil
}

func (layout Layout) input(role Role, phase Phase) string {
	return filepath.Join(
		layout.InputBase,
		string(role)+"-"+map[Phase]string{
			LayerAStage:        "layer-a",
			LayerASSHBootstrap: "ssh-bootstrap-layer-a",
			LayerBPrepare:      "layer-b-prepare",
			LayerBPin:          "layer-b-pin",
		}[phase],
	)
}

func (layout Layout) review(role Role) string {
	if role == ClientRole {
		return layout.ClientReview
	}
	return layout.PeerReview
}

func commandName(role Role, phase Phase) string {
	return "kyclash-vm-external-peer-lab-" + string(role) + "-" + map[Phase]string{
		LayerAStage:        "stage-layer-a",
		LayerASSHBootstrap: "bootstrap-ssh-layer-a",
		LayerBPrepare:      "prepare-layer-b",
		LayerBPin:          "pin-layer-b",
	}[phase]
}

func expectedInputNames(role Role, phase Phase) []string {
	command := commandName(role, phase)
	switch phase {
	case LayerAStage:
		if role == ClientRole {
			return []string{
				command,
				AppInputName,
				AppTreeManifestInputName,
				"kyclash-vm-external-peer-lab-supervisor",
				"kyclash-vm-external-peer-lab-harness",
				MihomoInputName,
				MihomoConfigInputName,
			}
		}
		return []string{
			command,
			"kyclash-vm-external-peer-lab-peer-root-supervisor",
			"kyclash-vm-external-peer-lab-peer",
			"kyclash-vm-external-peer-lab-listener-auditor",
			"kyclash-vm-external-peer-lab-forced-command",
		}
	case LayerASSHBootstrap:
		key := ClientManagementPublicKeyName
		if role == PeerRole {
			key = PeerManagementPublicKeyName
		}
		return []string{command, key}
	case LayerBPrepare:
		return []string{
			command,
			PeerConfigInputName,
			TicketExpectationInputName,
			CourierPublicKeyInputName,
		}
	case LayerBPin:
		return []string{
			command,
			PeerConfigInputName,
			TicketExpectationInputName,
			CourierPublicKeyInputName,
			ApprovedListenerBaselineName,
		}
	default:
		return nil
	}
}
