package externalpeergueststaging

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
)

type fileIdentity struct {
	Device           uint64
	Inode            uint64
	Size             uint64
	UID              uint32
	GID              uint32
	Mode             uint32
	Links            uint64
	ModifiedUnixNano int64
	SHA256           string
}

type createdRootFile struct {
	Path     string
	Identity fileIdentity
}

type stableDirectory struct {
	path     string
	file     *os.File
	identity os.FileInfo
	uid      uint32
	gid      uint32
	mode     os.FileMode
}

type stableBlob struct {
	bytes     []byte
	identity  fileIdentity
	directory *stableDirectory
	name      string
	mode      os.FileMode
}

type readHooks struct {
	afterRead     func(name string)
	beforeCommit  func()
	afterMutation func(label string) error
}

func identityFromInfo(info os.FileInfo) (fileIdentity, error) {
	if info == nil || info.Size() < 0 {
		return fileIdentity{}, ErrGuestStaging
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, ErrGuestStaging
	}
	return fileIdentity{
		Device:           uint64(stat.Dev),
		Inode:            uint64(stat.Ino),
		Size:             uint64(info.Size()),
		UID:              stat.Uid,
		GID:              stat.Gid,
		Mode:             uint32(info.Mode().Perm()),
		Links:            uint64(stat.Nlink),
		ModifiedUnixNano: info.ModTime().UnixNano(),
	}, nil
}

func openStableDirectory(
	path string,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) (*stableDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrGuestStaging
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, ErrGuestStaging
	}
	before, err := os.Lstat(path)
	if err != nil || !safeDirectoryInfo(before, uid, gid, mode) {
		return nil, ErrGuestStaging
	}
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrGuestStaging
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrGuestStaging
	}
	opened, openErr := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if openErr != nil || pathErr != nil ||
		!os.SameFile(before, opened) ||
		!os.SameFile(opened, pathAfter) ||
		!safeDirectoryInfo(opened, uid, gid, mode) ||
		!safeDirectoryInfo(pathAfter, uid, gid, mode) {
		_ = file.Close()
		return nil, ErrGuestStaging
	}
	return &stableDirectory{
		path: path, file: file, identity: opened,
		uid: uid, gid: gid, mode: mode.Perm(),
	}, nil
}

func openStableAppDirectory(
	parent *stableDirectory,
	name string,
) (*stableDirectory, error) {
	if parent == nil || parent.file == nil || !fixedBaseName(name) ||
		parent.revalidate() != nil {
		return nil, ErrGuestStaging
	}
	fd, err := unix.Openat(
		int(parent.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrGuestStaging
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrGuestStaging
	}
	info, err := file.Stat()
	path := filepath.Join(parent.path, name)
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil ||
		!os.SameFile(info, pathInfo) ||
		!safeAppDirectoryInfo(info, parent.uid, parent.gid) ||
		!safeAppDirectoryInfo(pathInfo, parent.uid, parent.gid) {
		_ = file.Close()
		return nil, ErrGuestStaging
	}
	return &stableDirectory{
		path: path, file: file, identity: info,
		uid: parent.uid, gid: parent.gid, mode: info.Mode().Perm(),
	}, nil
}

func (directory *stableDirectory) close() error {
	if directory == nil || directory.file == nil {
		return nil
	}
	err := directory.file.Close()
	directory.file = nil
	return err
}

func (directory *stableDirectory) revalidate() error {
	if directory == nil || directory.file == nil {
		return ErrGuestStaging
	}
	opened, err := directory.file.Stat()
	pathInfo, pathErr := os.Lstat(directory.path)
	if err != nil || pathErr != nil ||
		!os.SameFile(directory.identity, opened) ||
		!os.SameFile(opened, pathInfo) {
		return ErrGuestStaging
	}
	if directory.mode == inputDirectoryMode {
		if !safeDirectoryInfo(
			opened, directory.uid, directory.gid, directory.mode,
		) || !safeDirectoryInfo(
			pathInfo, directory.uid, directory.gid, directory.mode,
		) {
			return ErrGuestStaging
		}
	} else if !safeAppDirectoryInfo(opened, directory.uid, directory.gid) ||
		!safeAppDirectoryInfo(pathInfo, directory.uid, directory.gid) {
		return ErrGuestStaging
	}
	return nil
}

func (directory *stableDirectory) requireExactNames(expected []string) error {
	if len(expected) == 0 || directory.revalidate() != nil {
		return ErrGuestStaging
	}
	entries, err := directory.file.ReadDir(-1)
	if err != nil {
		return ErrGuestStaging
	}
	if _, err := directory.file.Seek(0, io.SeekStart); err != nil {
		return ErrGuestStaging
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !fixedBaseName(entry.Name()) {
			return ErrGuestStaging
		}
		actual = append(actual, entry.Name())
	}
	want := append([]string(nil), expected...)
	sort.Strings(actual)
	sort.Strings(want)
	if len(actual) != len(want) {
		return ErrGuestStaging
	}
	for index := range actual {
		if actual[index] != want[index] {
			return ErrGuestStaging
		}
	}
	return directory.revalidate()
}

func (directory *stableDirectory) readStableFile(
	name string,
	mode os.FileMode,
	maximum int64,
	afterRead func(string),
) (stableBlob, error) {
	if directory == nil || directory.file == nil ||
		!fixedBaseName(name) ||
		maximum <= 0 ||
		directory.revalidate() != nil {
		return stableBlob{}, ErrGuestStaging
	}
	fd, err := unix.Openat(
		int(directory.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return stableBlob{}, ErrGuestStaging
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return stableBlob{}, ErrGuestStaging
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil ||
		!safeRegularInfo(before, directory.uid, directory.gid, mode) ||
		before.Size() <= 0 ||
		before.Size() > maximum {
		return stableBlob{}, ErrGuestStaging
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != before.Size() || int64(len(data)) > maximum {
		clear(data)
		return stableBlob{}, ErrGuestStaging
	}
	if afterRead != nil {
		afterRead(name)
	}
	after, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(filepath.Join(directory.path, name))
	beforeID, beforeErr := identityFromInfo(before)
	afterID, afterErr := identityFromInfo(after)
	pathID, pathIDErr := identityFromInfo(pathInfo)
	if statErr != nil || pathErr != nil ||
		beforeErr != nil || afterErr != nil || pathIDErr != nil ||
		beforeID != afterID || afterID != pathID ||
		!os.SameFile(before, after) ||
		!os.SameFile(after, pathInfo) ||
		!safeRegularInfo(after, directory.uid, directory.gid, mode) ||
		!safeRegularInfo(pathInfo, directory.uid, directory.gid, mode) ||
		directory.revalidate() != nil {
		clear(data)
		return stableBlob{}, ErrGuestStaging
	}
	digest := sha256.Sum256(data)
	afterID.SHA256 = hex.EncodeToString(digest[:])
	return stableBlob{
		bytes: data, identity: afterID,
		directory: directory, name: name, mode: mode.Perm(),
	}, nil
}

func (blob stableBlob) revalidate() error {
	if blob.directory == nil || blob.directory.file == nil ||
		blob.directory.revalidate() != nil {
		return ErrGuestStaging
	}
	info, err := os.Lstat(filepath.Join(blob.directory.path, blob.name))
	identity, identityErr := identityFromInfo(info)
	identity.SHA256 = blob.identity.SHA256
	if err != nil || identityErr != nil ||
		identity != blob.identity ||
		!safeRegularInfo(
			info, blob.directory.uid, blob.directory.gid, blob.mode,
		) {
		return ErrGuestStaging
	}
	return nil
}

func (blob *stableBlob) clear() {
	if blob == nil {
		return
	}
	clear(blob.bytes)
	blob.bytes = nil
}

func safeDirectoryInfo(
	info os.FileInfo,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) bool {
	if info == nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != mode.Perm() {
		return false
	}
	identity, err := identityFromInfo(info)
	return err == nil &&
		identity.UID == uid &&
		identity.GID == gid &&
		identity.Links >= 1
}

func safeAppDirectoryInfo(
	info os.FileInfo,
	uid uint32,
	gid uint32,
) bool {
	if info == nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 ||
		info.Mode().Perm()&0o700 != 0o700 {
		return false
	}
	identity, err := identityFromInfo(info)
	return err == nil &&
		identity.UID == uid &&
		identity.GID == gid &&
		identity.Links >= 1
}

func safeRegularInfo(
	info os.FileInfo,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) bool {
	if info == nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != mode.Perm() {
		return false
	}
	identity, err := identityFromInfo(info)
	return err == nil &&
		identity.UID == uid &&
		identity.GID == gid &&
		identity.Links == 1
}

func fixedBaseName(name string) bool {
	return name != "" && name != "." && name != ".." &&
		filepath.Base(name) == name
}

func pathAbsent(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}

func ensureCreatedRootDirectory(
	path string,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) (*stableDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		!pathAbsent(path) ||
		requireSafeExistingParent(filepath.Dir(path), uid, gid) != nil {
		return nil, ErrGuestStaging
	}
	oldMask := unix.Umask(0o077)
	err := os.Mkdir(path, mode.Perm())
	unix.Umask(oldMask)
	if err != nil ||
		os.Chown(path, int(uid), int(gid)) != nil ||
		os.Chmod(path, mode.Perm()) != nil {
		return nil, ErrGuestStaging
	}
	return openStableDirectory(path, uid, gid, mode)
}

func requireSafeExistingParent(path string, uid uint32, gid uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrGuestStaging
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrGuestStaging
	}
	identity, err := identityFromInfo(info)
	if err != nil || identity.UID != uid || identity.GID != gid {
		return ErrGuestStaging
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return ErrGuestStaging
	}
	return nil
}

func createRootFile(
	path string,
	data []byte,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) (fileIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		pathAbsent(path) == false {
		return fileIdentity{}, ErrGuestStaging
	}
	parent, err := openStableDirectory(
		filepath.Dir(path), uid, gid,
		mustDirectoryMode(filepath.Dir(path)),
	)
	if err != nil {
		return fileIdentity{}, ErrGuestStaging
	}
	defer parent.close()
	name := filepath.Base(path)
	fd, err := unix.Openat(
		int(parent.file.Fd()),
		name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		uint32(mode.Perm()),
	)
	if err != nil {
		return fileIdentity{}, ErrGuestStaging
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return fileIdentity{}, ErrGuestStaging
	}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if file.Chown(int(uid), int(gid)) != nil ||
		file.Chmod(mode.Perm()) != nil {
		return fileIdentity{}, ErrGuestStaging
	}
	written, err := file.Write(data)
	if err != nil || written != len(data) || file.Sync() != nil {
		return fileIdentity{}, ErrGuestStaging
	}
	info, err := file.Stat()
	if err != nil ||
		!safeRegularInfo(info, uid, gid, mode) ||
		info.Size() != int64(len(data)) {
		return fileIdentity{}, ErrGuestStaging
	}
	if err := file.Close(); err != nil {
		return fileIdentity{}, ErrGuestStaging
	}
	failed = false
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, pathInfo) ||
		!safeRegularInfo(pathInfo, uid, gid, mode) ||
		parent.file.Sync() != nil ||
		parent.revalidate() != nil {
		return fileIdentity{}, ErrGuestStaging
	}
	identity, err := identityFromInfo(pathInfo)
	if err != nil {
		return fileIdentity{}, ErrGuestStaging
	}
	digest := sha256.Sum256(data)
	identity.SHA256 = hex.EncodeToString(digest[:])
	return identity, nil
}

func removeCreatedRootFile(created createdRootFile) error {
	if !filepath.IsAbs(created.Path) ||
		filepath.Clean(created.Path) != created.Path ||
		created.Identity.Device == 0 ||
		created.Identity.Inode == 0 {
		return ErrGuestStaging
	}
	info, err := os.Lstat(created.Path)
	if err != nil {
		return ErrGuestStaging
	}
	identity, err := identityFromInfo(info)
	if err != nil ||
		identity.Device != created.Identity.Device ||
		identity.Inode != created.Identity.Inode ||
		identity.Size != created.Identity.Size ||
		identity.UID != created.Identity.UID ||
		identity.GID != created.Identity.GID ||
		identity.Mode != created.Identity.Mode ||
		identity.Links != created.Identity.Links ||
		!safeRegularInfo(
			info,
			created.Identity.UID,
			created.Identity.GID,
			os.FileMode(created.Identity.Mode),
		) {
		return ErrGuestStaging
	}
	data, err := os.ReadFile(created.Path)
	if err != nil || hashHex(data) != created.Identity.SHA256 {
		clear(data)
		return ErrGuestStaging
	}
	clear(data)
	if err := os.Remove(created.Path); err != nil {
		return ErrGuestStaging
	}
	return nil
}

func readStableRootFile(
	path string,
	uid uint32,
	gid uint32,
	mode os.FileMode,
	maximum int64,
) (stableBlob, error) {
	parent, err := openStableDirectory(
		filepath.Dir(path), uid, gid,
		mustDirectoryMode(filepath.Dir(path)),
	)
	if err != nil {
		return stableBlob{}, ErrGuestStaging
	}
	blob, err := parent.readStableFile(
		filepath.Base(path), mode, maximum, nil,
	)
	if err != nil {
		_ = parent.close()
		return stableBlob{}, err
	}
	// The blob retains and revalidates the parent until its caller is done.
	return blob, nil
}

func mustDirectoryMode(path string) os.FileMode {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return 0
	}
	return info.Mode().Perm()
}

func validateThinArm64(data []byte) error {
	if len(data) < 32 ||
		data[0] != 0xcf || data[1] != 0xfa ||
		data[2] != 0xed || data[3] != 0xfe ||
		data[4] != 0x0c || data[5] != 0x00 ||
		data[6] != 0x00 || data[7] != 0x01 ||
		data[12] != 0x02 || data[13] != 0x00 ||
		data[14] != 0x00 || data[15] != 0x00 {
		return ErrGuestStaging
	}
	return nil
}
