package externalpeer

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
)

type StableDirectory struct {
	path string
	file *os.File
	uid  uint32
	mode os.FileMode
}

func OpenStableDirectory(
	path string,
	expectedUID uint32,
	mode os.FileMode,
) (*StableDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnsafeSupervisorFile
	}
	info, err := os.Lstat(path)
	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != mode.Perm() {
		return nil, ErrUnsafeSupervisorFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID || stat.Nlink < 1 {
		return nil, ErrUnsafeSupervisorFile
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnsafeSupervisorFile
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, ErrUnsafeSupervisorFile
	}
	return &StableDirectory{
		path: path,
		file: file,
		uid:  expectedUID,
		mode: mode.Perm(),
	}, nil
}

func (directory *StableDirectory) Close() error {
	if directory == nil || directory.file == nil {
		return nil
	}
	err := directory.file.Close()
	directory.file = nil
	return err
}

func (directory *StableDirectory) ReadCreateOnlyFile(
	name string,
	maximum int,
	expectedMode os.FileMode,
) ([]byte, error) {
	if directory == nil ||
		directory.file == nil ||
		!validArtifactName(name) ||
		maximum <= 0 ||
		maximum > MaxChildControlFrame {
		return nil, ErrUnsafeSupervisorFile
	}
	fd, err := unix.Openat(
		int(directory.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrUnsafeSupervisorFile
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrUnsafeSupervisorFile
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !safeStableFile(before, directory.uid, expectedMode) {
		return nil, ErrUnsafeSupervisorFile
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum+1)))
	if err != nil || len(data) > maximum || int64(len(data)) != before.Size() {
		clear(data)
		return nil, ErrUnsafeSupervisorFile
	}
	after, err := file.Stat()
	if err != nil ||
		!os.SameFile(before, after) ||
		before.Size() != after.Size() ||
		before.ModTime() != after.ModTime() {
		clear(data)
		return nil, ErrUnsafeSupervisorFile
	}
	pathInfo, err := os.Lstat(filepath.Join(directory.path, name))
	if err != nil || !os.SameFile(before, pathInfo) ||
		!safeStableFile(pathInfo, directory.uid, expectedMode) {
		clear(data)
		return nil, ErrUnsafeSupervisorFile
	}
	return data, nil
}

func (directory *StableDirectory) RequireExactNames(names []string) error {
	if directory == nil || directory.file == nil {
		return ErrUnsafeSupervisorFile
	}
	entries, err := directory.file.ReadDir(-1)
	if err != nil {
		return ErrUnsafeSupervisorFile
	}
	if _, err := directory.file.Seek(0, io.SeekStart); err != nil {
		return ErrUnsafeSupervisorFile
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		actual = append(actual, entry.Name())
	}
	expected := append([]string(nil), names...)
	sort.Strings(actual)
	sort.Strings(expected)
	if len(actual) != len(expected) {
		return ErrUnsafeSupervisorFile
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return ErrUnsafeSupervisorFile
		}
	}
	return nil
}

func (directory *StableDirectory) RemoveExact(name string) error {
	return directory.RemoveExactMode(name, 0o600)
}

func (directory *StableDirectory) RemoveExactMode(
	name string,
	mode os.FileMode,
) error {
	if directory == nil || directory.file == nil || !validArtifactName(name) {
		return ErrUnsafeSupervisorFile
	}
	fd, err := unix.Openat(
		int(directory.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return ErrUnsafeSupervisorFile
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return ErrUnsafeSupervisorFile
	}
	info, statErr := file.Stat()
	_ = file.Close()
	if statErr != nil || !safeStableFile(info, directory.uid, mode) {
		return ErrUnsafeSupervisorFile
	}
	if err := unix.Unlinkat(int(directory.file.Fd()), name, 0); err != nil {
		return ErrUnsafeSupervisorFile
	}
	return directory.file.Sync()
}

func (directory *StableDirectory) CreateExactFile(
	name string,
	data []byte,
	mode os.FileMode,
) error {
	if directory == nil ||
		directory.file == nil ||
		!validArtifactName(name) ||
		len(data) > MaxChildControlFrame {
		return ErrUnsafeSupervisorFile
	}
	fd, err := unix.Openat(
		int(directory.file.Fd()),
		name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		uint32(mode.Perm()),
	)
	if err != nil {
		return ErrUnsafeSupervisorFile
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return ErrUnsafeSupervisorFile
	}
	if err := file.Chmod(mode.Perm()); err != nil {
		_ = file.Close()
		return ErrUnsafeSupervisorFile
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return ErrUnsafeSupervisorFile
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return ErrUnsafeSupervisorFile
	}
	info, err := file.Stat()
	closeErr := file.Close()
	if err != nil ||
		closeErr != nil ||
		!safeStableFile(info, directory.uid, mode) ||
		info.Size() != int64(len(data)) {
		return ErrUnsafeSupervisorFile
	}
	pathInfo, err := os.Lstat(filepath.Join(directory.path, name))
	if err != nil ||
		!os.SameFile(info, pathInfo) ||
		!safeStableFile(pathInfo, directory.uid, mode) {
		return ErrUnsafeSupervisorFile
	}
	return directory.file.Sync()
}

func safeStableFile(info os.FileInfo, expectedUID uint32, mode os.FileMode) bool {
	if info == nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != mode.Perm() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == expectedUID && stat.Nlink == 1
}
