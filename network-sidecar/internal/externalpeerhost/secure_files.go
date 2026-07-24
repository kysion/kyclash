package externalpeerhost

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
)

type secureDirectory struct {
	path     string
	file     *os.File
	identity os.FileInfo
	uid      uint32
}

type fileWitness struct {
	directory *secureDirectory
	name      string
	identity  os.FileInfo
	mode      os.FileMode
}

type secureBlob struct {
	bytes   []byte
	witness fileWitness
}

func openSecureDirectory(path string, expectedUID uint32) (*secureDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnsafeHostCourier
	}
	before, err := os.Lstat(path)
	if err != nil || !safeDirectoryInfo(before, expectedUID) {
		return nil, ErrUnsafeHostCourier
	}
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrUnsafeHostCourier
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrUnsafeHostCourier
	}
	opened, err := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil ||
		!os.SameFile(before, opened) ||
		!os.SameFile(opened, pathAfter) ||
		!safeDirectoryInfo(opened, expectedUID) ||
		!safeDirectoryInfo(pathAfter, expectedUID) {
		_ = file.Close()
		return nil, ErrUnsafeHostCourier
	}
	return &secureDirectory{
		path:     path,
		file:     file,
		identity: opened,
		uid:      expectedUID,
	}, nil
}

func (directory *secureDirectory) close() error {
	if directory == nil || directory.file == nil {
		return nil
	}
	err := directory.file.Close()
	directory.file = nil
	return err
}

func (directory *secureDirectory) revalidate() error {
	if directory == nil || directory.file == nil {
		return ErrUnsafeHostCourier
	}
	opened, err := directory.file.Stat()
	pathInfo, pathErr := os.Lstat(directory.path)
	if err != nil || pathErr != nil ||
		!os.SameFile(directory.identity, opened) ||
		!os.SameFile(opened, pathInfo) ||
		!safeDirectoryInfo(opened, directory.uid) ||
		!safeDirectoryInfo(pathInfo, directory.uid) {
		return ErrUnsafeHostCourier
	}
	return nil
}

func (directory *secureDirectory) requireExactNames(expected []string) error {
	if err := directory.revalidate(); err != nil {
		return err
	}
	entries, err := directory.file.ReadDir(-1)
	if err != nil {
		return ErrUnsafeHostCourier
	}
	if _, err := directory.file.Seek(0, io.SeekStart); err != nil {
		return ErrUnsafeHostCourier
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		actual = append(actual, entry.Name())
	}
	want := append([]string(nil), expected...)
	sort.Strings(actual)
	sort.Strings(want)
	if len(actual) != len(want) {
		return ErrUnsafeHostCourier
	}
	for index := range actual {
		if actual[index] != want[index] {
			return ErrUnsafeHostCourier
		}
	}
	return directory.revalidate()
}

// readStableFile has a deliberately unexported afterRead hook so the
// replacement/TOCTOU refusal can be tested deterministically. Production
// callers always pass nil.
func (directory *secureDirectory) readStableFile(
	name string,
	maximum int,
	afterRead func(),
) (secureBlob, error) {
	if directory == nil || directory.file == nil ||
		!fixedBaseName(name) || maximum <= 0 ||
		maximum > maximumHostArtifactBytes ||
		directory.revalidate() != nil {
		return secureBlob{}, ErrUnsafeHostCourier
	}
	fd, err := unix.Openat(
		int(directory.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return secureBlob{}, ErrUnsafeHostCourier
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return secureBlob{}, ErrUnsafeHostCourier
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil ||
		!safeRegularInfo(before, directory.uid, secureFileMode) ||
		before.Size() < 0 ||
		before.Size() > int64(maximum) {
		return secureBlob{}, ErrUnsafeHostCourier
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum+1)))
	if err != nil || len(data) > maximum || int64(len(data)) != before.Size() {
		clear(data)
		return secureBlob{}, ErrUnsafeHostCourier
	}
	if afterRead != nil {
		afterRead()
	}
	after, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(filepath.Join(directory.path, name))
	if statErr != nil || pathErr != nil ||
		!os.SameFile(before, after) ||
		!os.SameFile(after, pathInfo) ||
		before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) ||
		!after.ModTime().Equal(pathInfo.ModTime()) ||
		!safeRegularInfo(after, directory.uid, secureFileMode) ||
		!safeRegularInfo(pathInfo, directory.uid, secureFileMode) ||
		directory.revalidate() != nil {
		clear(data)
		return secureBlob{}, ErrUnsafeHostCourier
	}
	return secureBlob{
		bytes: data,
		witness: fileWitness{
			directory: directory,
			name:      name,
			identity:  after,
			mode:      secureFileMode,
		},
	}, nil
}

func (directory *secureDirectory) witnessStableFile(
	name string,
	minimum int64,
	maximum int64,
) (fileWitness, error) {
	if directory == nil || directory.file == nil ||
		!fixedBaseName(name) ||
		minimum < 0 || maximum < minimum ||
		directory.revalidate() != nil {
		return fileWitness{}, ErrUnsafeHostCourier
	}
	fd, err := unix.Openat(
		int(directory.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fileWitness{}, ErrUnsafeHostCourier
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return fileWitness{}, ErrUnsafeHostCourier
	}
	before, err := file.Stat()
	if err != nil ||
		!safeRegularInfo(before, directory.uid, secureFileMode) ||
		before.Size() < minimum ||
		before.Size() > maximum {
		_ = file.Close()
		return fileWitness{}, ErrUnsafeHostCourier
	}
	after, statErr := file.Stat()
	closeErr := file.Close()
	pathInfo, pathErr := os.Lstat(filepath.Join(directory.path, name))
	if statErr != nil || closeErr != nil || pathErr != nil ||
		!os.SameFile(before, after) ||
		!os.SameFile(after, pathInfo) ||
		before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) ||
		!after.ModTime().Equal(pathInfo.ModTime()) ||
		!safeRegularInfo(pathInfo, directory.uid, secureFileMode) ||
		directory.revalidate() != nil {
		return fileWitness{}, ErrUnsafeHostCourier
	}
	return fileWitness{
		directory: directory,
		name:      name,
		identity:  pathInfo,
		mode:      secureFileMode,
	}, nil
}

func (witness fileWitness) revalidate() error {
	if witness.directory == nil || witness.identity == nil ||
		witness.directory.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	pathInfo, err := os.Lstat(filepath.Join(witness.directory.path, witness.name))
	if err != nil ||
		!os.SameFile(witness.identity, pathInfo) ||
		witness.identity.Size() != pathInfo.Size() ||
		!witness.identity.ModTime().Equal(pathInfo.ModTime()) ||
		!safeRegularInfo(pathInfo, witness.directory.uid, witness.mode) {
		return ErrUnsafeHostCourier
	}
	return nil
}

func (directory *secureDirectory) createExactFile(
	name string,
	data []byte,
) (fileWitness, error) {
	if directory == nil || directory.file == nil ||
		!fixedBaseName(name) ||
		len(data) > maximumHostArtifactBytes ||
		directory.revalidate() != nil {
		return fileWitness{}, ErrUnsafeHostCourier
	}
	fd, err := unix.Openat(
		int(directory.file.Fd()),
		name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		secureFileMode,
	)
	if err != nil {
		return fileWitness{}, ErrUnsafeHostCourier
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return fileWitness{}, ErrUnsafeHostCourier
	}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	if err := file.Chmod(secureFileMode); err != nil {
		return fileWitness{}, ErrUnsafeHostCourier
	}
	written, err := file.Write(data)
	if err != nil || written != len(data) || file.Sync() != nil {
		return fileWitness{}, ErrUnsafeHostCourier
	}
	info, err := file.Stat()
	if err != nil ||
		!safeRegularInfo(info, directory.uid, secureFileMode) ||
		info.Size() != int64(len(data)) {
		return fileWitness{}, ErrUnsafeHostCourier
	}
	if err := file.Close(); err != nil {
		return fileWitness{}, ErrUnsafeHostCourier
	}
	failed = false
	pathInfo, err := os.Lstat(filepath.Join(directory.path, name))
	if err != nil ||
		!os.SameFile(info, pathInfo) ||
		!safeRegularInfo(pathInfo, directory.uid, secureFileMode) ||
		info.Size() != pathInfo.Size() ||
		!info.ModTime().Equal(pathInfo.ModTime()) ||
		directory.file.Sync() != nil ||
		directory.revalidate() != nil {
		return fileWitness{}, ErrUnsafeHostCourier
	}
	return fileWitness{
		directory: directory,
		name:      name,
		identity:  pathInfo,
		mode:      secureFileMode,
	}, nil
}

func (directory *secureDirectory) removeWitness(witness fileWitness) error {
	if witness.directory != directory || witness.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	if err := unix.Unlinkat(int(directory.file.Fd()), witness.name, 0); err != nil {
		return ErrUnsafeHostCourier
	}
	return directory.file.Sync()
}

func safeDirectoryInfo(info os.FileInfo, expectedUID uint32) bool {
	if info == nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != secureDirectoryMode {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == expectedUID && stat.Nlink >= 1
}

func safeRegularInfo(
	info os.FileInfo,
	expectedUID uint32,
	expectedMode os.FileMode,
) bool {
	if info == nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != expectedMode.Perm() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == expectedUID && stat.Nlink == 1
}

func fixedBaseName(name string) bool {
	return name != "" && filepath.Base(name) == name &&
		name != "." && name != ".."
}

func ensurePrivateRoot(path string, expectedUID uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrUnsafeHostCourier
	}
	if err := os.MkdirAll(filepath.Dir(path), secureDirectoryMode); err != nil {
		return ErrUnsafeHostCourier
	}
	if err := os.Mkdir(path, secureDirectoryMode); err != nil &&
		!errors.Is(err, os.ErrExist) {
		return ErrUnsafeHostCourier
	}
	directory, err := openSecureDirectory(path, expectedUID)
	if err != nil {
		return err
	}
	return directory.close()
}

func pathAbsent(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}

// InitializeKeyStore creates one raw Ed25519 courier key pair with
// create-only semantics. It never opens or reuses a pre-existing private key.
func InitializeKeyStore(layout Layout, entropy io.Reader) error {
	if entropy == nil {
		entropy = rand.Reader
	}
	uid := uint32(os.Getuid())
	if err := ensurePrivateRoot(layout.PrivateRoot, uid); err != nil {
		return err
	}
	directory, err := openSecureDirectory(layout.PrivateRoot, uid)
	if err != nil {
		return err
	}
	defer directory.close()
	lock, err := directory.createExactFile(keyInitializationLock, nil)
	if err != nil {
		return err
	}
	lockPresent := true
	defer func() {
		if lockPresent {
			_ = directory.removeWitness(lock)
		}
	}()
	if !pathAbsent(filepath.Join(layout.PrivateRoot, PrivateKeyName)) ||
		!pathAbsent(filepath.Join(layout.PrivateRoot, PublicKeyName)) {
		return ErrUnsafeHostCourier
	}
	publicKey, privateKey, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return ErrUnsafeHostCourier
	}
	defer clear(privateKey)
	privateWitness, err := directory.createExactFile(PrivateKeyName, privateKey)
	if err != nil {
		return err
	}
	publicWitness, err := directory.createExactFile(PublicKeyName, publicKey)
	if err != nil {
		_ = directory.removeWitness(privateWitness)
		return err
	}
	if privateWitness.revalidate() != nil || publicWitness.revalidate() != nil {
		_ = directory.removeWitness(publicWitness)
		_ = directory.removeWitness(privateWitness)
		return ErrUnsafeHostCourier
	}
	if err := directory.removeWitness(lock); err != nil {
		return err
	}
	lockPresent = false
	return nil
}

type loadedKeyPair struct {
	private        ed25519.PrivateKey
	public         ed25519.PublicKey
	privateWitness fileWitness
	publicWitness  fileWitness
	directory      *secureDirectory
}

func loadKeyPair(layout Layout) (*loadedKeyPair, error) {
	directory, err := openSecureDirectory(layout.PrivateRoot, uint32(os.Getuid()))
	if err != nil {
		return nil, err
	}
	privateBlob, err := directory.readStableFile(
		PrivateKeyName,
		ed25519.PrivateKeySize,
		nil,
	)
	if err != nil || len(privateBlob.bytes) != ed25519.PrivateKeySize {
		clear(privateBlob.bytes)
		_ = directory.close()
		return nil, ErrUnsafeHostCourier
	}
	publicBlob, err := directory.readStableFile(
		PublicKeyName,
		ed25519.PublicKeySize,
		nil,
	)
	if err != nil || len(publicBlob.bytes) != ed25519.PublicKeySize {
		clear(privateBlob.bytes)
		clear(publicBlob.bytes)
		_ = directory.close()
		return nil, ErrUnsafeHostCourier
	}
	privateKey := ed25519.PrivateKey(privateBlob.bytes)
	publicKey := ed25519.PublicKey(publicBlob.bytes)
	derived, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || !equalBytes(derived, publicKey) {
		clear(privateKey)
		clear(publicKey)
		_ = directory.close()
		return nil, ErrUnsafeHostCourier
	}
	return &loadedKeyPair{
		private:        privateKey,
		public:         publicKey,
		privateWitness: privateBlob.witness,
		publicWitness:  publicBlob.witness,
		directory:      directory,
	}, nil
}

func (keys *loadedKeyPair) revalidate() error {
	if keys == nil ||
		keys.privateWitness.revalidate() != nil ||
		keys.publicWitness.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	return nil
}

func (keys *loadedKeyPair) close() {
	if keys == nil {
		return
	}
	clear(keys.private)
	clear(keys.public)
	_ = keys.directory.close()
	*keys = loadedKeyPair{}
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
