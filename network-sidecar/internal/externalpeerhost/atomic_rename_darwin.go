//go:build darwin

package externalpeerhost

import "golang.org/x/sys/unix"

func renameDirectoryNoReplace(source string, destination string) error {
	if err := unix.RenameatxNp(
		unix.AT_FDCWD,
		source,
		unix.AT_FDCWD,
		destination,
		unix.RENAME_EXCL,
	); err != nil {
		return ErrUnsafeHostCourier
	}
	return nil
}
