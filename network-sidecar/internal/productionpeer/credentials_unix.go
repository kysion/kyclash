//go:build linux || darwin

package productionpeer

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// ReadLinuxConfig performs the fixed, stable public-config open used by the
// Linux command. It returns bytes so the descriptor and directory-entry
// identity can be rechecked after the bounded read and before JSON decoding.
func ReadLinuxConfig() ([]byte, error) {
	return readStablePublicConfigAt(
		LinuxConfigDirectory,
		LinuxConfigFileName,
		MaxConfigSize,
		0,
	)
}

func readStablePublicConfigAt(directory, name string, maximum int64, expectedUID uint32) ([]byte, error) {
	if name != LinuxConfigFileName || maximum <= 0 {
		return nil, ErrInvalidConfig
	}
	encoded, err := readStableFileAt(directory, name, maximum, expectedUID, 0o022)
	if err != nil {
		clear(encoded)
		return nil, ErrInvalidConfig
	}
	return encoded, nil
}

func readStableFileAt(
	directory string,
	name string,
	maximum int64,
	expectedUID uint32,
	forbiddenMode uint32,
) ([]byte, error) {
	directoryDescriptor, err := unix.Open(
		directory,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY,
		0,
	)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	defer unix.Close(directoryDescriptor)
	var directoryFacts unix.Stat_t
	if unix.Fstat(directoryDescriptor, &directoryFacts) != nil ||
		directoryFacts.Mode&unix.S_IFMT != unix.S_IFDIR ||
		directoryFacts.Uid != expectedUID ||
		directoryFacts.Mode&0o022 != 0 {
		return nil, ErrCredentialUnavailable
	}

	descriptor, err := unix.Openat(
		directoryDescriptor,
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrCredentialUnavailable
	}
	defer file.Close()

	var openedFacts unix.Stat_t
	var namedFacts unix.Stat_t
	if unix.Fstat(descriptor, &openedFacts) != nil ||
		unix.Fstatat(directoryDescriptor, name, &namedFacts, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!stableFileFactsValid(
			uint32(openedFacts.Mode),
			openedFacts.Uid,
			openedFacts.Size,
			expectedUID,
			maximum,
			forbiddenMode,
		) ||
		!sameStableFileIdentity(&openedFacts, &namedFacts) {
		return nil, ErrCredentialUnavailable
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil ||
		int64(len(encoded)) != openedFacts.Size {
		clear(encoded)
		return nil, ErrCredentialUnavailable
	}

	var finalOpenedFacts unix.Stat_t
	var finalNamedFacts unix.Stat_t
	if unix.Fstat(descriptor, &finalOpenedFacts) != nil ||
		unix.Fstatat(directoryDescriptor, name, &finalNamedFacts, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!sameStableFileIdentity(&openedFacts, &finalOpenedFacts) ||
		!sameStableFileIdentity(&openedFacts, &finalNamedFacts) ||
		finalOpenedFacts.Size != int64(len(encoded)) {
		clear(encoded)
		return nil, ErrCredentialUnavailable
	}
	return encoded, nil
}

func stableFileFactsValid(
	mode uint32,
	uid uint32,
	size int64,
	expectedUID uint32,
	maximum int64,
	forbiddenMode uint32,
) bool {
	return mode&unix.S_IFMT == unix.S_IFREG &&
		uid == expectedUID &&
		mode&forbiddenMode == 0 &&
		size > 0 &&
		size <= maximum
}

func sameStableFileIdentity(left, right *unix.Stat_t) bool {
	return left != nil &&
		right != nil &&
		left.Dev == right.Dev &&
		left.Ino == right.Ino &&
		left.Mode == right.Mode &&
		left.Uid == right.Uid &&
		left.Gid == right.Gid
}
