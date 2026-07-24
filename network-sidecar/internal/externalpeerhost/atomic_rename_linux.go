//go:build linux

package externalpeerhost

import "golang.org/x/sys/unix"

func renameDirectoryNoReplace(source string, destination string) error {
	if err := unix.Renameat2(
		unix.AT_FDCWD,
		source,
		unix.AT_FDCWD,
		destination,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return ErrUnsafeHostCourier
	}
	return nil
}
