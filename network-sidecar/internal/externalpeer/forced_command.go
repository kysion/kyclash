package externalpeer

import (
	"errors"
	"io"
	"os"
	"syscall"
)

func ReadFixedRunNonce() ([]byte, error) {
	info, err := os.Lstat(PeerRunNoncePath)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o444 ||
		info.Size() != 32 {
		return nil, ErrUnsafeSupervisorFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return nil, ErrUnsafeSupervisorFile
	}
	file, err := os.OpenFile(PeerRunNoncePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsafeSupervisorFile
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrUnsafeSupervisorFile
	}
	nonce, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(nonce) != 32 {
		clear(nonce)
		return nil, ErrUnsafeSupervisorFile
	}
	after, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(PeerRunNoncePath)
	if statErr != nil || pathErr != nil ||
		!os.SameFile(opened, after) ||
		!os.SameFile(opened, pathInfo) ||
		after.Size() != 32 {
		clear(nonce)
		return nil, ErrUnsafeSupervisorFile
	}
	return nonce, nil
}

func RunForcedCommand(originalCommand string, output io.Writer) error {
	if originalCommand != ForcedCommandName || output == nil {
		return ErrSSHProof
	}
	nonce, err := ReadFixedRunNonce()
	if err != nil {
		return err
	}
	defer clear(nonce)
	written, err := output.Write(nonce)
	if err != nil || written != len(nonce) {
		return errors.Join(ErrSSHProof, err)
	}
	return nil
}
