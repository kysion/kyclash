package externalpeerhost

import (
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
)

func TestRemoteCommandBindsStableParentDirectoryContract(t *testing.T) {
	t.Parallel()
	role := roleContract{
		role: "client",
		facts: externalpeer.CourierVMFacts{
			PlatformUUID:       "11111111-2222-3333-4444-555555555555",
			SSHHostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			MAC:                [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
			IPv4:               [4]byte{192, 168, 64, 3},
		},
		consoleUID: 501,
	}
	path := filepath.Join(
		vmexternalpeerlab.ClientInboxRoot,
		vmexternalpeerlab.RunTicketName,
	)
	contract, err := lookupRemoteContract(
		role.consoleUID,
		role.role,
		path,
		remoteActionCreate,
	)
	if err != nil {
		t.Fatal(err)
	}
	command := buildRemoteCommand(
		role,
		contract,
		remoteActionCreate,
		time.Unix(1_700_000_000, 0).UTC(),
	)
	values, err := parseFixedShellQuotedCommand(command)
	if err != nil || len(values) != 17 {
		t.Fatal("remote command did not retain its closed argument shape")
	}
	if values[4] != path ||
		values[7] != netip.AddrFrom4(role.facts.IPv4).String() ||
		values[15] != strconv.FormatUint(uint64(role.consoleUID), 10) ||
		values[16] != "0700" {
		t.Fatal("remote command did not bind its stable parent contract")
	}
}

func TestRemoteProgramUsesDirFDAndCleansCreateOnIdentityFailure(t *testing.T) {
	t.Parallel()
	for _, required := range []string{
		"os.O_DIRECTORY | flags",
		"dir_fd=parent_fd",
		"directory_witness(parent_before)",
		"directory_witness(parent_after)",
		"os.unlink(name, dir_fd=parent_fd)",
		"os.stat(name, dir_fd=parent_fd, follow_symlinks=False)",
	} {
		if !strings.Contains(remotePythonProgram, required) {
			t.Fatalf("remote program is missing closed-parent operation %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.open(path,",
		"os.lstat(path)",
		"os.rename(path",
		"shell=True",
	} {
		if strings.Contains(remotePythonProgram, forbidden) {
			t.Fatalf("remote program regained redirected path operation %q", forbidden)
		}
	}
}
