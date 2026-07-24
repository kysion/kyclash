package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/kysion/kyclash/network-sidecar/internal/bootstrap"
	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/identifier"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
)

const (
	inheritedAppFD        = 3
	inheritedSupervisorFD = 4
	fixedAppExecutable    = "/Applications/KyClash.app/Contents/MacOS/clash-verge"
)

var fixedTransportOrder = [...]string{"quic", "wss", "tcp"}

func clearTLSCertificate(certificate *tls.Certificate) {
	if certificate == nil {
		return
	}
	for _, encoded := range certificate.Certificate {
		clear(encoded)
	}
	clear(certificate.OCSPStaple)
	for _, timestamp := range certificate.SignedCertificateTimestamps {
		clear(timestamp)
	}
	if privateKey, ok := certificate.PrivateKey.(ed25519.PrivateKey); ok {
		clear(privateKey)
	}
	*certificate = tls.Certificate{}
}

type runtimeFacts struct {
	GOOS         string
	GOARCH       string
	EffectiveUID int
	ConsoleUID   int
	Model        string
	WorkingDir   string
	Environment  []string
}

type redactedHandshake struct {
	ProtocolVersion uint8    `json:"protocol_version"`
	InstanceID      string   `json:"instance_id"`
	AuthProof       string   `json:"auth_proof"`
	RuntimeMode     string   `json:"runtime_mode"`
	TunnelKind      string   `json:"tunnel_kind"`
	PeerVM          string   `json:"peer_vm"`
	MihomoDevice    string   `json:"mihomo_device"`
	TransportOrder  []string `json:"transport_order"`
}

func validateArguments(arguments []string) error {
	if len(arguments) != 0 {
		return errors.New("command-line arguments are not accepted")
	}
	return nil
}

func validateRuntimeFacts(facts runtimeFacts) error {
	if facts.GOOS != "darwin" || facts.GOARCH != "arm64" ||
		facts.EffectiveUID != 0 || facts.ConsoleUID <= 0 ||
		facts.WorkingDir != "/" || len(facts.Environment) != 0 ||
		!strings.HasPrefix(strings.TrimSpace(facts.Model), "VirtualMac") {
		return errors.New("fixed root VirtualMac client runtime is required")
	}
	return nil
}

func newRedactedHandshake(instanceID, authProof string) (redactedHandshake, error) {
	value := redactedHandshake{
		ProtocolVersion: bootstrap.ProtocolVersion,
		InstanceID:      instanceID,
		AuthProof:       authProof,
		RuntimeMode:     vmexternalpeerlab.RuntimeMode,
		TunnelKind:      vmexternalpeerlab.TunnelKind,
		PeerVM:          vmexternalpeerlab.PeerRuntimeTarget,
		MihomoDevice:    vmexternalpeerlab.MihomoInterface,
		TransportOrder:  append([]string(nil), fixedTransportOrder[:]...),
	}
	if err := value.Validate(); err != nil {
		return redactedHandshake{}, err
	}
	return value, nil
}

func (value redactedHandshake) Validate() error {
	if value.ProtocolVersion != bootstrap.ProtocolVersion ||
		!identifier.Valid(value.InstanceID) ||
		!validLowerSHA256(value.AuthProof) ||
		value.RuntimeMode != vmexternalpeerlab.RuntimeMode ||
		value.TunnelKind != vmexternalpeerlab.TunnelKind ||
		value.PeerVM != vmexternalpeerlab.PeerRuntimeTarget ||
		value.MihomoDevice != vmexternalpeerlab.MihomoInterface ||
		len(value.TransportOrder) != len(fixedTransportOrder) {
		return errors.New("invalid redacted external-peer handshake")
	}
	for index := range fixedTransportOrder {
		if value.TransportOrder[index] != fixedTransportOrder[index] {
			return errors.New("invalid redacted transport order")
		}
	}
	return nil
}

func validLowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	valid := err == nil && len(decoded) == sha256.Size &&
		hex.EncodeToString(decoded) == value
	clear(decoded)
	return valid
}

func runIDFromEntropy(entropy []byte) (string, error) {
	if len(entropy) != 16 {
		return "", errors.New("invalid run entropy")
	}
	return "run-" + hex.EncodeToString(entropy), nil
}

func validatePinnedClientFacts(
	observed externalpeer.CourierVMFacts,
	expected externalpeer.CourierVMFacts,
) error {
	if observed != expected ||
		observed.Role != "client" ||
		observed.VMName != externalpeer.ClientVMName {
		return errors.New("observed client VM facts differ from pinned config")
	}
	return nil
}

func matchTicketArtifact(
	expectation externalpeer.RunTicketExpectation,
	name string,
	length uint64,
	digest string,
) error {
	if expectation.Validate() != nil || !validLowerSHA256(digest) {
		return errors.New("invalid ticket artifact observation")
	}
	for _, expected := range expectation.Files {
		if expected.Name == name {
			if expected.Length != length || expected.SHA256 != digest {
				return errors.New("local artifact differs from ticket expectation")
			}
			return nil
		}
	}
	return errors.New("local artifact is absent from ticket expectation")
}
