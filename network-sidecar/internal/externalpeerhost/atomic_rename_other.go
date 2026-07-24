//go:build !darwin && !linux

package externalpeerhost

func renameDirectoryNoReplace(string, string) error {
	return ErrUnsafeHostCourier
}
