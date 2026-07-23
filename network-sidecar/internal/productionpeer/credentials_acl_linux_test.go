//go:build linux

package productionpeer

import (
	"encoding/binary"
	"testing"
)

type systemdCredentialACLEntryForTest struct {
	tag         uint16
	permissions uint16
	id          uint32
}

func encodeSystemdCredentialACLForTest(
	version uint32,
	entries ...systemdCredentialACLEntryForTest,
) []byte {
	encoded := make(
		[]byte,
		systemdCredentialACLHeaderSize+len(entries)*systemdCredentialACLEntrySize,
	)
	binary.LittleEndian.PutUint32(encoded[:systemdCredentialACLHeaderSize], version)
	for index, entry := range entries {
		offset := systemdCredentialACLHeaderSize + index*systemdCredentialACLEntrySize
		binary.LittleEndian.PutUint16(encoded[offset:offset+2], entry.tag)
		binary.LittleEndian.PutUint16(encoded[offset+2:offset+4], entry.permissions)
		binary.LittleEndian.PutUint32(encoded[offset+4:offset+8], entry.id)
	}
	return encoded
}

func validSystemdCredentialACLEntriesForTest(
	peerUID uint32,
	permissions uint16,
) []systemdCredentialACLEntryForTest {
	return []systemdCredentialACLEntryForTest{
		{
			tag:         systemdCredentialACLUserObject,
			permissions: permissions,
			id:          systemdCredentialACLUndefinedID,
		},
		{
			tag:         systemdCredentialACLNamedUser,
			permissions: permissions,
			id:          peerUID,
		},
		{
			tag:         systemdCredentialACLGroupObject,
			permissions: 0,
			id:          systemdCredentialACLUndefinedID,
		},
		{
			tag:         systemdCredentialACLMask,
			permissions: permissions,
			id:          systemdCredentialACLUndefinedID,
		},
		{
			tag:         systemdCredentialACLOther,
			permissions: 0,
			id:          systemdCredentialACLUndefinedID,
		},
	}
}

func TestValidateSystemdCredentialACLAcceptsExactEntries(t *testing.T) {
	t.Parallel()

	const peerUID = 64210
	for _, test := range []struct {
		name        string
		permissions uint16
	}{
		{name: "file", permissions: systemdCredentialACLRead},
		{
			name:        "directory",
			permissions: systemdCredentialACLRead | systemdCredentialACLExecute,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			encoded := encodeSystemdCredentialACLForTest(
				systemdCredentialACLVersion,
				validSystemdCredentialACLEntriesForTest(peerUID, test.permissions)...,
			)
			if !validateSystemdCredentialACL(encoded, peerUID, test.permissions) {
				t.Fatal("exact systemd credential access ACL was rejected")
			}
		})
	}
}

func TestValidateSystemdCredentialACLAcceptsEntryOrderChanges(t *testing.T) {
	t.Parallel()

	const (
		peerUID     = 64210
		permissions = systemdCredentialACLRead | systemdCredentialACLExecute
	)
	entries := validSystemdCredentialACLEntriesForTest(peerUID, permissions)
	shuffled := []systemdCredentialACLEntryForTest{
		entries[4],
		entries[1],
		entries[3],
		entries[0],
		entries[2],
	}
	encoded := encodeSystemdCredentialACLForTest(systemdCredentialACLVersion, shuffled...)
	if !validateSystemdCredentialACL(encoded, peerUID, permissions) {
		t.Fatal("valid order-independent systemd credential access ACL was rejected")
	}
}

func TestValidateSystemdCredentialACLRejectsMalformedOrExpandedACLs(t *testing.T) {
	t.Parallel()

	const (
		peerUID     = 64210
		permissions = systemdCredentialACLRead
	)
	validEntries := validSystemdCredentialACLEntriesForTest(peerUID, permissions)
	valid := encodeSystemdCredentialACLForTest(systemdCredentialACLVersion, validEntries...)

	cloneEntries := func() []systemdCredentialACLEntryForTest {
		return append([]systemdCredentialACLEntryForTest(nil), validEntries...)
	}

	tests := []struct {
		name        string
		encoded     []byte
		uid         uint32
		permissions uint16
	}{
		{name: "empty", encoded: nil, uid: peerUID, permissions: permissions},
		{name: "truncated header", encoded: []byte{2, 0, 0}, uid: peerUID, permissions: permissions},
		{name: "truncated entry", encoded: valid[:len(valid)-1], uid: peerUID, permissions: permissions},
		{
			name: "bad version",
			encoded: encodeSystemdCredentialACLForTest(
				systemdCredentialACLVersion+1,
				validEntries...,
			),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "duplicate user object",
			encoded: func() []byte {
				entries := cloneEntries()
				entries[3] = entries[0]
				return encodeSystemdCredentialACLForTest(systemdCredentialACLVersion, entries...)
			}(),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "extra named user",
			encoded: encodeSystemdCredentialACLForTest(
				systemdCredentialACLVersion,
				append(cloneEntries(), systemdCredentialACLEntryForTest{
					tag:         systemdCredentialACLNamedUser,
					permissions: permissions,
					id:          peerUID + 1,
				})...,
			),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "named group",
			encoded: encodeSystemdCredentialACLForTest(
				systemdCredentialACLVersion,
				append(cloneEntries(), systemdCredentialACLEntryForTest{
					tag:         systemdCredentialACLNamedGroup,
					permissions: permissions,
					id:          peerUID + 1,
				})...,
			),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "named group within exact entry count",
			encoded: func() []byte {
				entries := cloneEntries()
				entries[1] = systemdCredentialACLEntryForTest{
					tag:         systemdCredentialACLNamedGroup,
					permissions: permissions,
					id:          peerUID,
				}
				return encodeSystemdCredentialACLForTest(systemdCredentialACLVersion, entries...)
			}(),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "unknown tag",
			encoded: func() []byte {
				entries := cloneEntries()
				entries[1].tag = 0x0040
				return encodeSystemdCredentialACLForTest(systemdCredentialACLVersion, entries...)
			}(),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "wrong named user",
			encoded: func() []byte {
				entries := cloneEntries()
				entries[1].id = peerUID + 1
				return encodeSystemdCredentialACLForTest(systemdCredentialACLVersion, entries...)
			}(),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "missing mask",
			encoded: encodeSystemdCredentialACLForTest(
				systemdCredentialACLVersion,
				validEntries[:3]...,
			),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "owner permission drift",
			encoded: func() []byte {
				entries := cloneEntries()
				entries[0].permissions |= systemdCredentialACLExecute
				return encodeSystemdCredentialACLForTest(systemdCredentialACLVersion, entries...)
			}(),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "named user permission drift",
			encoded: func() []byte {
				entries := cloneEntries()
				entries[1].permissions |= systemdCredentialACLWrite
				return encodeSystemdCredentialACLForTest(systemdCredentialACLVersion, entries...)
			}(),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "mask permission drift",
			encoded: func() []byte {
				entries := cloneEntries()
				entries[3].permissions = 0
				return encodeSystemdCredentialACLForTest(systemdCredentialACLVersion, entries...)
			}(),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "group object access",
			encoded: func() []byte {
				entries := cloneEntries()
				entries[2].permissions = systemdCredentialACLRead
				return encodeSystemdCredentialACLForTest(systemdCredentialACLVersion, entries...)
			}(),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "other access",
			encoded: func() []byte {
				entries := cloneEntries()
				entries[4].permissions = systemdCredentialACLRead
				return encodeSystemdCredentialACLForTest(systemdCredentialACLVersion, entries...)
			}(),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name: "structural ID set",
			encoded: func() []byte {
				entries := cloneEntries()
				entries[0].id = 0
				return encodeSystemdCredentialACLForTest(systemdCredentialACLVersion, entries...)
			}(),
			uid:         peerUID,
			permissions: permissions,
		},
		{
			name:        "root peer UID",
			encoded:     valid,
			uid:         0,
			permissions: permissions,
		},
		{
			name:        "undefined peer UID",
			encoded:     valid,
			uid:         systemdCredentialACLUndefinedID,
			permissions: permissions,
		},
		{
			name: "write-bearing requested permissions",
			encoded: encodeSystemdCredentialACLForTest(
				systemdCredentialACLVersion,
				validSystemdCredentialACLEntriesForTest(
					peerUID,
					systemdCredentialACLRead|systemdCredentialACLWrite,
				)...,
			),
			uid:         peerUID,
			permissions: systemdCredentialACLRead | systemdCredentialACLWrite,
		},
		{
			name:        "unsupported requested permissions",
			encoded:     valid,
			uid:         peerUID,
			permissions: systemdCredentialACLExecute,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if validateSystemdCredentialACL(test.encoded, test.uid, test.permissions) {
				t.Fatal("invalid systemd credential access ACL was accepted")
			}
		})
	}
}

func FuzzValidateSystemdCredentialACLDoesNotPanic(f *testing.F) {
	const peerUID = 64210
	valid := encodeSystemdCredentialACLForTest(
		systemdCredentialACLVersion,
		validSystemdCredentialACLEntriesForTest(peerUID, systemdCredentialACLRead)...,
	)
	f.Add(valid, uint32(peerUID), uint16(systemdCredentialACLRead))
	f.Add([]byte(nil), uint32(0), uint16(0))
	f.Add([]byte{2, 0, 0}, ^uint32(0), ^uint16(0))

	f.Fuzz(func(t *testing.T, encoded []byte, uid uint32, permissions uint16) {
		_ = validateSystemdCredentialACL(encoded, uid, permissions)
	})
}
