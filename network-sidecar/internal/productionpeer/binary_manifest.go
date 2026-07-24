package productionpeer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"unicode/utf8"
)

const (
	binaryIdentityManifestSchemaVersionV1 = 1
	binaryIdentityManifestMaxSizeV1       = 4 * 1024
)

var errBinaryIdentityManifestUnavailableV1 = errors.New("production peer binary identity manifest unavailable")

type binaryIdentityManifestJSONV1 struct {
	SchemaVersion uint8                                `json:"schema_version"`
	PeerUID       uint32                               `json:"peer_uid"`
	BrokerUID     uint32                               `json:"broker_uid"`
	IPCGID        uint32                               `json:"ipc_gid"`
	Binaries      binaryIdentityManifestBinariesJSONV1 `json:"binaries"`
}

type binaryIdentityManifestBinariesJSONV1 struct {
	PeerSHA256          string `json:"peer_sha256"`
	BrokerSHA256        string `json:"broker_sha256"`
	HostBootstrapSHA256 string `json:"host_bootstrap_sha256"`
}

// binaryIdentityManifestV1 is deliberately private and has no production
// caller. A later invocation-identity capability must compose it with the
// fixed systemd unit and pidfd proof before any live loader can become active.
type binaryIdentityManifestV1 struct {
	peerUID             uint32
	brokerUID           uint32
	ipcGID              uint32
	manifestSHA256      [32]byte
	peerSHA256          [32]byte
	brokerSHA256        [32]byte
	hostBootstrapSHA256 [32]byte
}

func decodeBinaryIdentityManifestV1(encoded []byte) (binaryIdentityManifestV1, error) {
	if len(encoded) == 0 ||
		len(encoded) > binaryIdentityManifestMaxSizeV1 ||
		!utf8.Valid(encoded) ||
		!uniqueJSONKeys(encoded) ||
		!exactBinaryIdentityManifestKeysV1(encoded) {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire binaryIdentityManifestJSONV1
	if err := decoder.Decode(&wire); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}

	peerDigest, peerOK := decodeCanonicalSHA256V1(wire.Binaries.PeerSHA256)
	brokerDigest, brokerOK := decodeCanonicalSHA256V1(wire.Binaries.BrokerSHA256)
	hostBootstrapDigest, hostBootstrapOK := decodeCanonicalSHA256V1(
		wire.Binaries.HostBootstrapSHA256,
	)
	if wire.SchemaVersion != binaryIdentityManifestSchemaVersionV1 ||
		!validBinaryIdentityIDV1(wire.PeerUID) ||
		!validBinaryIdentityIDV1(wire.BrokerUID) ||
		!validBinaryIdentityIDV1(wire.IPCGID) ||
		wire.PeerUID == wire.BrokerUID ||
		!peerOK ||
		!brokerOK ||
		!hostBootstrapOK {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}

	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return binaryIdentityManifestV1{}, errBinaryIdentityManifestUnavailableV1
	}

	return binaryIdentityManifestV1{
		peerUID:             wire.PeerUID,
		brokerUID:           wire.BrokerUID,
		ipcGID:              wire.IPCGID,
		peerSHA256:          peerDigest,
		brokerSHA256:        brokerDigest,
		hostBootstrapSHA256: hostBootstrapDigest,
	}, nil
}

func exactBinaryIdentityManifestKeysV1(encoded []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return false
	}
	root, ok := exactConfigJSONObject(decoded, []string{
		"schema_version",
		"peer_uid",
		"broker_uid",
		"ipc_gid",
		"binaries",
	})
	if !ok {
		return false
	}
	_, ok = exactConfigJSONObject(root["binaries"], []string{
		"peer_sha256",
		"broker_sha256",
		"host_bootstrap_sha256",
	})
	return ok
}

func decodeCanonicalSHA256V1(encoded string) ([32]byte, bool) {
	var decoded [32]byte
	if len(encoded) != hex.EncodedLen(len(decoded)) {
		return [32]byte{}, false
	}
	count, err := hex.Decode(decoded[:], []byte(encoded))
	if err != nil || count != len(decoded) || hex.EncodeToString(decoded[:]) != encoded {
		return [32]byte{}, false
	}
	return decoded, true
}

func validBinaryIdentityIDV1(identifier uint32) bool {
	return identifier != 0 && identifier != math.MaxUint32
}
