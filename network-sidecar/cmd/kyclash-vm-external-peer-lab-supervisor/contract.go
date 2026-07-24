package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
)

const (
	appManifestSchemaVersion = vmexternalpeerlab.AppManifestSchemaVersion
	maximumAppManifestSize   = vmexternalpeerlab.MaximumAppManifestSize
	expectedAppExecutable    = vmexternalpeerlab.AppExecutablePath
	clientListenerBaseline   = externalpeer.ClientListenerBaselinePath
	childAppFD               = 3
	childSupervisorFD        = 4
)

type appManifest = vmexternalpeerlab.AppManifestV2

type runtimeFacts struct {
	GOOS          string
	GOARCH        string
	EffectiveUID  int
	ConsoleUID    int
	Model         string
	Runner        string
	Confirmation  string
	RuntimeTarget string
}

func validateArguments(arguments []string) error {
	if len(arguments) != 0 {
		return errors.New("command-line arguments are not accepted")
	}
	return nil
}

func validateRuntimeFacts(facts runtimeFacts) error {
	if facts.GOOS != "darwin" || facts.GOARCH != "arm64" ||
		facts.EffectiveUID != 0 || facts.ConsoleUID <= 0 {
		return errors.New("root arm64 macOS with an interactive console user is required")
	}
	if !strings.HasPrefix(strings.TrimSpace(facts.Model), "VirtualMac") {
		return errors.New("the selected disposable VirtualMac guest is required")
	}
	if facts.Runner != vmexternalpeerlab.RunnerEnv ||
		facts.Confirmation != vmexternalpeerlab.VMConfirmation ||
		facts.RuntimeTarget != vmexternalpeerlab.RuntimeTarget {
		return errors.New("the exact external-peer client VM confirmation is required")
	}
	return nil
}

func decodeAppManifest(reader io.Reader) (appManifest, error) {
	return vmexternalpeerlab.DecodeAppManifestV2(reader)
}

func rejectDuplicateManifestKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("App manifest is not an object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return errors.New("invalid App manifest key")
		}
		if _, exists := seen[key]; exists {
			return errors.New("duplicate App manifest key")
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return errors.New("invalid App manifest value")
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return errors.New("unterminated App manifest")
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return errors.New("App manifest contains trailing data")
	}
	return nil
}

func validateHarnessObservation(
	manifest appManifest,
	device uint64,
	inode uint64,
	size uint64,
	digest string,
) error {
	if manifest.Validate() != nil ||
		device != manifest.HarnessExecutableDevice ||
		inode != manifest.HarnessExecutableInode ||
		size != manifest.HarnessExecutableSize ||
		digest != manifest.HarnessExecutableSHA256 {
		return errors.New("harness executable differs from App manifest")
	}
	return nil
}

func matchTicketExecutable(
	expectation externalpeer.RunTicketExpectation,
	name string,
	size uint64,
	digest string,
) error {
	if expectation.Validate() != nil || !validLowerSHA256(digest) {
		return errors.New("invalid executable ticket observation")
	}
	for _, artifact := range expectation.Files {
		if artifact.Name == name {
			if artifact.Length != size || artifact.SHA256 != digest {
				return fmt.Errorf("%s executable differs from run ticket", name)
			}
			return nil
		}
	}
	return errors.New("executable is absent from run ticket")
}

func validLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validateThinArm64Executable(header []byte) error {
	if len(header) < 32 ||
		!bytes.Equal(header[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) ||
		!bytes.Equal(header[4:8], []byte{0x0c, 0x00, 0x00, 0x01}) ||
		!bytes.Equal(header[12:16], []byte{0x02, 0x00, 0x00, 0x00}) {
		return errors.New("executable is not a thin arm64 Mach-O")
	}
	return nil
}

func fixedHarnessInvocation() (string, []string, []string, string) {
	return vmexternalpeerlab.HarnessPath,
		[]string{vmexternalpeerlab.HarnessPath},
		[]string{},
		"/"
}

func productionRuntimeFacts(effectiveUID, consoleUID int, model string) runtimeFacts {
	return runtimeFacts{
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		EffectiveUID: effectiveUID, ConsoleUID: consoleUID, Model: model,
	}
}
