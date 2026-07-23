//go:build linux

package productionpeer

import "encoding/binary"

const (
	systemdCredentialACLVersion    uint32 = 0x0002
	systemdCredentialACLHeaderSize        = 4
	systemdCredentialACLEntrySize         = 8

	systemdCredentialACLUserObject  uint16 = 0x0001
	systemdCredentialACLNamedUser   uint16 = 0x0002
	systemdCredentialACLGroupObject uint16 = 0x0004
	systemdCredentialACLNamedGroup  uint16 = 0x0008
	systemdCredentialACLMask        uint16 = 0x0010
	systemdCredentialACLOther       uint16 = 0x0020

	systemdCredentialACLExecute uint16 = 0x0001
	systemdCredentialACLWrite   uint16 = 0x0002
	systemdCredentialACLRead    uint16 = 0x0004

	systemdCredentialACLUndefinedID uint32 = ^uint32(0)
)

// validateSystemdCredentialACL validates the exact POSIX access ACL emitted
// for the root-owned systemd credential materialization accepted by the
// locked Linux Peer v2 profile. Default ACL presence is checked separately by
// the descriptor-bound xattr reader.
func validateSystemdCredentialACL(encoded []byte, peerUID uint32, permissions uint16) bool {
	const exactEntryCount = 5

	if peerUID == 0 || peerUID == systemdCredentialACLUndefinedID {
		return false
	}
	if permissions != systemdCredentialACLRead &&
		permissions != systemdCredentialACLRead|systemdCredentialACLExecute {
		return false
	}
	if len(encoded) != systemdCredentialACLHeaderSize+exactEntryCount*systemdCredentialACLEntrySize {
		return false
	}
	if binary.LittleEndian.Uint32(encoded[:systemdCredentialACLHeaderSize]) != systemdCredentialACLVersion {
		return false
	}

	var (
		seenUserObject  bool
		seenNamedUser   bool
		seenGroupObject bool
		seenMask        bool
		seenOther       bool
	)
	for offset := systemdCredentialACLHeaderSize; offset < len(encoded); offset += systemdCredentialACLEntrySize {
		entry := encoded[offset : offset+systemdCredentialACLEntrySize]
		tag := binary.LittleEndian.Uint16(entry[0:2])
		entryPermissions := binary.LittleEndian.Uint16(entry[2:4])
		id := binary.LittleEndian.Uint32(entry[4:8])

		switch tag {
		case systemdCredentialACLUserObject:
			if seenUserObject ||
				entryPermissions != permissions ||
				id != systemdCredentialACLUndefinedID {
				return false
			}
			seenUserObject = true
		case systemdCredentialACLNamedUser:
			if seenNamedUser ||
				entryPermissions != permissions ||
				id != peerUID {
				return false
			}
			seenNamedUser = true
		case systemdCredentialACLGroupObject:
			if seenGroupObject ||
				entryPermissions != 0 ||
				id != systemdCredentialACLUndefinedID {
				return false
			}
			seenGroupObject = true
		case systemdCredentialACLMask:
			if seenMask ||
				entryPermissions != permissions ||
				id != systemdCredentialACLUndefinedID {
				return false
			}
			seenMask = true
		case systemdCredentialACLOther:
			if seenOther ||
				entryPermissions != 0 ||
				id != systemdCredentialACLUndefinedID {
				return false
			}
			seenOther = true
		case systemdCredentialACLNamedGroup:
			return false
		default:
			return false
		}
	}

	return seenUserObject &&
		seenNamedUser &&
		seenGroupObject &&
		seenMask &&
		seenOther
}
