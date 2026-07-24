package productionpeer

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const canonicalBinaryIdentityManifestV1ForTest = `{"schema_version":1,"peer_uid":64210,"broker_uid":64211,"ipc_gid":64212,"binaries":{"peer_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","broker_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","host_bootstrap_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}`

func TestDecodeBinaryIdentityManifestV1AcceptsOnlyCanonicalSchema(t *testing.T) {
	t.Parallel()

	decoded, err := decodeBinaryIdentityManifestV1(
		[]byte(canonicalBinaryIdentityManifestV1ForTest),
	)
	if err != nil {
		t.Fatalf("canonical binary identity manifest was rejected: %v", err)
	}
	if decoded.peerUID != 64210 ||
		decoded.brokerUID != 64211 ||
		decoded.ipcGID != 64212 ||
		decoded.peerSHA256 != [32]byte{
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		} ||
		decoded.brokerSHA256 != [32]byte{
			0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
			0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
			0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
			0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
		} ||
		decoded.hostBootstrapSHA256 != [32]byte{
			0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
		} {
		t.Fatal("canonical binary identity manifest decoded to unexpected facts")
	}
}

func TestDecodeBinaryIdentityManifestV1RejectsExpandedOrNoncanonicalJSON(t *testing.T) {
	t.Parallel()

	valid := canonicalBinaryIdentityManifestV1ForTest
	cases := map[string]string{
		"empty":               "",
		"leading whitespace":  " " + valid,
		"trailing whitespace": valid + "\n",
		"trailing object":     valid + `{}`,
		"reordered root fields": strings.Replace(
			valid,
			`"schema_version":1,"peer_uid":64210`,
			`"peer_uid":64210,"schema_version":1`,
			1,
		),
		"noncanonical number": strings.Replace(valid, `"peer_uid":64210`, `"peer_uid":6.421e4`, 1),
		"escaped key":         strings.Replace(valid, `"schema_version"`, `"\u0073chema_version"`, 1),
		"unknown root field": strings.Replace(
			valid,
			`"binaries":`,
			`"unexpected":false,"binaries":`,
			1,
		),
		"unknown nested field": strings.Replace(
			valid,
			`"peer_sha256":`,
			`"unexpected":false,"peer_sha256":`,
			1,
		),
		"duplicate root field": strings.Replace(
			valid,
			`"peer_uid":64210`,
			`"peer_uid":64210,"peer_uid":64210`,
			1,
		),
		"duplicate nested field": strings.Replace(
			valid,
			`"peer_sha256":"`+strings.Repeat("a", 64)+`"`,
			`"peer_sha256":"`+strings.Repeat("a", 64)+`","peer_sha256":"`+strings.Repeat("a", 64)+`"`,
			1,
		),
		"missing root field": strings.Replace(valid, `"ipc_gid":64212,`, "", 1),
		"missing nested field": strings.Replace(
			valid,
			`"broker_sha256":"`+strings.Repeat("b", 64)+`",`,
			"",
			1,
		),
		"array root": `[]`,
		"array binaries": strings.Replace(
			valid,
			`{"peer_sha256":"`+strings.Repeat("a", 64)+`","broker_sha256":"`+strings.Repeat("b", 64)+`","host_bootstrap_sha256":"`+strings.Repeat("c", 64)+`"}`,
			`[]`,
			1,
		),
		"invalid utf8": valid + string([]byte{0xff}),
	}
	for name, encoded := range cases {
		name, encoded := name, encoded
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			decoded, err := decodeBinaryIdentityManifestV1([]byte(encoded))
			if !errors.Is(err, errBinaryIdentityManifestUnavailableV1) ||
				decoded != (binaryIdentityManifestV1{}) {
				t.Fatalf("invalid manifest escaped: decoded=%#v err=%v", decoded, err)
			}
		})
	}

	oversized := bytes.Repeat([]byte{' '}, binaryIdentityManifestMaxSizeV1+1)
	decoded, err := decodeBinaryIdentityManifestV1(oversized)
	if !errors.Is(err, errBinaryIdentityManifestUnavailableV1) ||
		decoded != (binaryIdentityManifestV1{}) {
		t.Fatalf("oversized manifest escaped: decoded=%#v err=%v", decoded, err)
	}
}

func TestDecodeBinaryIdentityManifestV1RejectsInvalidIdentityRolesAndDigests(t *testing.T) {
	t.Parallel()

	valid := canonicalBinaryIdentityManifestV1ForTest
	cases := map[string]string{
		"schema":                strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1),
		"zero peer":             strings.Replace(valid, `"peer_uid":64210`, `"peer_uid":0`, 1),
		"reserved peer":         strings.Replace(valid, `"peer_uid":64210`, `"peer_uid":4294967295`, 1),
		"zero broker":           strings.Replace(valid, `"broker_uid":64211`, `"broker_uid":0`, 1),
		"reserved broker":       strings.Replace(valid, `"broker_uid":64211`, `"broker_uid":4294967295`, 1),
		"same service uid":      strings.Replace(valid, `"broker_uid":64211`, `"broker_uid":64210`, 1),
		"zero ipc group":        strings.Replace(valid, `"ipc_gid":64212`, `"ipc_gid":0`, 1),
		"reserved ipc group":    strings.Replace(valid, `"ipc_gid":64212`, `"ipc_gid":4294967295`, 1),
		"short peer digest":     strings.Replace(valid, strings.Repeat("a", 64), strings.Repeat("a", 63), 1),
		"uppercase peer digest": strings.Replace(valid, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"nonhex broker digest":  strings.Replace(valid, strings.Repeat("b", 64), strings.Repeat("z", 64), 1),
		"long host digest":      strings.Replace(valid, strings.Repeat("c", 64), strings.Repeat("c", 65), 1),
	}
	for name, encoded := range cases {
		name, encoded := name, encoded
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			decoded, err := decodeBinaryIdentityManifestV1([]byte(encoded))
			if !errors.Is(err, errBinaryIdentityManifestUnavailableV1) ||
				decoded != (binaryIdentityManifestV1{}) {
				t.Fatalf("invalid manifest escaped: decoded=%#v err=%v", decoded, err)
			}
		})
	}
}

func FuzzDecodeBinaryIdentityManifestV1DoesNotPanic(f *testing.F) {
	f.Add([]byte(canonicalBinaryIdentityManifestV1ForTest))
	f.Add([]byte(`{}`))
	f.Fuzz(func(_ *testing.T, encoded []byte) {
		_, _ = decodeBinaryIdentityManifestV1(encoded)
	})
}
