package vmexternalpeerlab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	MaximumCanonicalAppTreeManifestSize = 4 * 1024 * 1024
	maximumCanonicalAppEntries          = 4096
	maximumCanonicalAppDepth            = 16
	maximumCanonicalAppFileSize         = 512 * 1024 * 1024
)

type canonicalAppBuildSource struct {
	Commit       string `json:"commit"`
	Dirty        bool   `json:"dirty"`
	StatusSHA256 string `json:"status_sha256"`
	TreeSHA256   string `json:"tree_sha256"`
	FileCount    int    `json:"file_count"`
}

type canonicalAppInfoPlist struct {
	RelativePath     string `json:"relative_path"`
	BundleIdentifier string `json:"bundle_identifier"`
	ShortVersion     string `json:"short_version"`
	BundleVersion    string `json:"bundle_version"`
	BundleExecutable string `json:"bundle_executable"`
}

type canonicalAppExecutable struct {
	RelativePath string `json:"relative_path"`
	Mode         string `json:"mode"`
	ByteLength   uint64 `json:"byte_length"`
	SHA256       string `json:"sha256"`
}

type canonicalAppTreeEntry struct {
	RelativePath string  `json:"relative_path"`
	Type         string  `json:"type"`
	Mode         string  `json:"mode"`
	ByteLength   uint64  `json:"byte_length"`
	SHA256       *string `json:"sha256"`
}

type canonicalAppTreeManifest struct {
	SchemaVersion  uint8                   `json:"schema_version"`
	AppName        string                  `json:"app_name"`
	Source         canonicalAppBuildSource `json:"source"`
	TreeSHA256     string                  `json:"tree_sha256"`
	InfoPlist      canonicalAppInfoPlist   `json:"info_plist"`
	MainExecutable canonicalAppExecutable  `json:"main_executable"`
	Entries        []canonicalAppTreeEntry `json:"entries"`
}

// VerifyCanonicalAppTree binds the root-owned App tree to both the canonical
// build manifest bytes and its entries-array digest. It rejects missing,
// additional, reordered, symlinked, hard-linked, re-owned, re-moded, or
// byte-changed entries.
func VerifyCanonicalAppTree(
	appRoot string,
	manifestBytes []byte,
	expectedManifestSHA256 string,
	expectedTreeSHA256 string,
	uid uint32,
	gid uint32,
) error {
	if !filepath.IsAbs(appRoot) ||
		filepath.Clean(appRoot) != appRoot ||
		!validLowerSHA256(expectedManifestSHA256) ||
		!validLowerSHA256(expectedTreeSHA256) ||
		hashCanonicalBytes(manifestBytes) != expectedManifestSHA256 {
		return ErrInvalidAppManifest
	}
	manifest, err := decodeCanonicalAppTreeManifest(manifestBytes)
	if err != nil || manifest.TreeSHA256 != expectedTreeSHA256 {
		return ErrInvalidAppManifest
	}
	root, err := openCanonicalTreeRoot(appRoot, uid, gid)
	if err != nil {
		return err
	}
	defer root.close()
	actual, err := collectCanonicalAppTree(root)
	if err != nil || len(actual) != len(manifest.Entries) {
		return ErrInvalidAppManifest
	}
	for index := range actual {
		if !equalCanonicalAppTreeEntry(actual[index], manifest.Entries[index]) {
			return ErrInvalidAppManifest
		}
	}
	encoded, err := json.Marshal(actual)
	if err != nil ||
		hashCanonicalBytes(encoded) != manifest.TreeSHA256 ||
		root.revalidate() != nil {
		return ErrInvalidAppManifest
	}
	return nil
}

func decodeCanonicalAppTreeManifest(
	data []byte,
) (canonicalAppTreeManifest, error) {
	if len(data) == 0 ||
		len(data) > MaximumCanonicalAppTreeManifestSize ||
		rejectDuplicateCanonicalJSONKeys(data) != nil {
		return canonicalAppTreeManifest{}, ErrInvalidAppManifest
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest canonicalAppTreeManifest
	if decoder.Decode(&manifest) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		validateCanonicalAppTreeManifest(manifest) != nil {
		return canonicalAppTreeManifest{}, ErrInvalidAppManifest
	}
	return manifest, nil
}

func validateCanonicalAppTreeManifest(
	manifest canonicalAppTreeManifest,
) error {
	if manifest.SchemaVersion != 1 ||
		manifest.AppName != "KyClash.app" ||
		len(manifest.Source.Commit) != 40 ||
		!validLowerHex(manifest.Source.Commit) ||
		!validLowerSHA256(manifest.Source.StatusSHA256) ||
		!validLowerSHA256(manifest.Source.TreeSHA256) ||
		manifest.Source.FileCount <= 0 ||
		!validLowerSHA256(manifest.TreeSHA256) ||
		manifest.InfoPlist.RelativePath != "Contents/Info.plist" ||
		manifest.InfoPlist.BundleIdentifier != "net.kysion.kyclash" ||
		manifest.InfoPlist.BundleExecutable != "clash-verge" ||
		!validCanonicalManifestString(manifest.InfoPlist.ShortVersion) ||
		!validCanonicalManifestString(manifest.InfoPlist.BundleVersion) ||
		manifest.MainExecutable.RelativePath !=
			"Contents/MacOS/clash-verge" ||
		manifest.MainExecutable.Mode != "0755" ||
		manifest.MainExecutable.ByteLength < 32 ||
		manifest.MainExecutable.ByteLength >
			maximumCanonicalAppFileSize ||
		!validLowerSHA256(manifest.MainExecutable.SHA256) ||
		len(manifest.Entries) == 0 ||
		len(manifest.Entries) > maximumCanonicalAppEntries {
		return ErrInvalidAppManifest
	}
	encoded, err := json.Marshal(manifest.Entries)
	if err != nil || hashCanonicalBytes(encoded) != manifest.TreeSHA256 {
		return ErrInvalidAppManifest
	}
	parents := map[string]struct{}{".": {}}
	previous := ""
	var info *canonicalAppTreeEntry
	var executable *canonicalAppTreeEntry
	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		if !validCanonicalAppRelativePath(entry.RelativePath) ||
			index > 0 &&
				bytes.Compare(
					[]byte(previous),
					[]byte(entry.RelativePath),
				) >= 0 ||
			(entry.Type != "directory" && entry.Type != "file") ||
			!validCanonicalAppMode(entry.Mode) {
			return ErrInvalidAppManifest
		}
		if index == 0 {
			if entry.RelativePath != "." ||
				entry.Type != "directory" ||
				entry.Mode != "0755" {
				return ErrInvalidAppManifest
			}
		} else if _, exists := parents[filepath.Dir(entry.RelativePath)]; !exists {
			return ErrInvalidAppManifest
		}
		if entry.Type == "directory" {
			if entry.Mode != "0755" ||
				entry.ByteLength != 0 ||
				entry.SHA256 != nil {
				return ErrInvalidAppManifest
			}
			parents[entry.RelativePath] = struct{}{}
		} else if entry.SHA256 == nil ||
			entry.ByteLength > maximumCanonicalAppFileSize ||
			!validLowerSHA256(*entry.SHA256) {
			return ErrInvalidAppManifest
		}
		if entry.RelativePath == manifest.InfoPlist.RelativePath {
			info = entry
		}
		if entry.RelativePath == manifest.MainExecutable.RelativePath {
			executable = entry
		}
		previous = entry.RelativePath
	}
	if info == nil ||
		info.Type != "file" ||
		info.Mode != "0644" ||
		executable == nil ||
		executable.Type != "file" ||
		executable.Mode != manifest.MainExecutable.Mode ||
		executable.ByteLength != manifest.MainExecutable.ByteLength ||
		executable.SHA256 == nil ||
		*executable.SHA256 != manifest.MainExecutable.SHA256 {
		return ErrInvalidAppManifest
	}
	return nil
}

func validCanonicalManifestString(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character <= 0x1f || character == 0x7f {
			return false
		}
	}
	return true
}

func validCanonicalAppRelativePath(value string) bool {
	return value != "" &&
		!filepath.IsAbs(value) &&
		filepath.Clean(value) == value &&
		!strings.Contains(value, `\`) &&
		!strings.ContainsRune(value, 0) &&
		(value == "." || !strings.HasPrefix(value, "../"))
}

func validCanonicalAppMode(value string) bool {
	if len(value) != 4 || value[0] != '0' {
		return false
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	return err == nil && (parsed == 0o644 || parsed == 0o755)
}

func validLowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func hashCanonicalBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func rejectDuplicateCanonicalJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var readValue func() error
	readValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return ErrInvalidAppManifest
		}
		delim, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, ok := keyToken.(string)
				if keyErr != nil || !ok {
					return ErrInvalidAppManifest
				}
				if _, exists := seen[key]; exists {
					return ErrInvalidAppManifest
				}
				seen[key] = struct{}{}
				if err := readValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrInvalidAppManifest
			}
		case '[':
			for decoder.More() {
				if err := readValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return ErrInvalidAppManifest
			}
		default:
			return ErrInvalidAppManifest
		}
		return nil
	}
	if readValue() != nil {
		return ErrInvalidAppManifest
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return ErrInvalidAppManifest
	}
	return nil
}

type canonicalTreeDirectory struct {
	path     string
	file     *os.File
	identity os.FileInfo
	uid      uint32
	gid      uint32
}

func openCanonicalTreeRoot(
	path string,
	uid uint32,
	gid uint32,
) (*canonicalTreeDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalidAppManifest
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, ErrInvalidAppManifest
	}
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrInvalidAppManifest
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrInvalidAppManifest
	}
	info, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil ||
		pathErr != nil ||
		!os.SameFile(info, pathInfo) ||
		!safeCanonicalDirectory(info, uid, gid) ||
		!safeCanonicalDirectory(pathInfo, uid, gid) {
		_ = file.Close()
		return nil, ErrInvalidAppManifest
	}
	return &canonicalTreeDirectory{
		path: path, file: file, identity: info, uid: uid, gid: gid,
	}, nil
}

func openCanonicalTreeChild(
	parent *canonicalTreeDirectory,
	name string,
) (*canonicalTreeDirectory, error) {
	if parent == nil ||
		parent.revalidate() != nil ||
		!fixedCanonicalBaseName(name) {
		return nil, ErrInvalidAppManifest
	}
	fd, err := unix.Openat(
		int(parent.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrInvalidAppManifest
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrInvalidAppManifest
	}
	info, err := file.Stat()
	path := filepath.Join(parent.path, name)
	pathInfo, pathErr := os.Lstat(path)
	if err != nil ||
		pathErr != nil ||
		!os.SameFile(info, pathInfo) ||
		!safeCanonicalDirectory(info, parent.uid, parent.gid) ||
		!safeCanonicalDirectory(pathInfo, parent.uid, parent.gid) {
		_ = file.Close()
		return nil, ErrInvalidAppManifest
	}
	return &canonicalTreeDirectory{
		path: path, file: file, identity: info,
		uid: parent.uid, gid: parent.gid,
	}, nil
}

func (directory *canonicalTreeDirectory) revalidate() error {
	if directory == nil || directory.file == nil {
		return ErrInvalidAppManifest
	}
	opened, err := directory.file.Stat()
	pathInfo, pathErr := os.Lstat(directory.path)
	if err != nil ||
		pathErr != nil ||
		!os.SameFile(directory.identity, opened) ||
		!os.SameFile(opened, pathInfo) ||
		!safeCanonicalDirectory(opened, directory.uid, directory.gid) ||
		!safeCanonicalDirectory(pathInfo, directory.uid, directory.gid) {
		return ErrInvalidAppManifest
	}
	return nil
}

func (directory *canonicalTreeDirectory) close() error {
	if directory == nil || directory.file == nil {
		return nil
	}
	err := directory.file.Close()
	directory.file = nil
	return err
}

func safeCanonicalDirectory(
	info os.FileInfo,
	uid uint32,
	gid uint32,
) bool {
	if info == nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o755 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Gid == gid
}

func collectCanonicalAppTree(
	root *canonicalTreeDirectory,
) ([]canonicalAppTreeEntry, error) {
	if root == nil || root.revalidate() != nil {
		return nil, ErrInvalidAppManifest
	}
	result := []canonicalAppTreeEntry{{
		RelativePath: ".", Type: "directory", Mode: "0755",
		ByteLength: 0, SHA256: nil,
	}}
	var visit func(*canonicalTreeDirectory, string, int) error
	visit = func(
		directory *canonicalTreeDirectory,
		prefix string,
		depth int,
	) error {
		if depth > maximumCanonicalAppDepth ||
			directory.revalidate() != nil {
			return ErrInvalidAppManifest
		}
		entries, err := directory.file.ReadDir(-1)
		if err != nil {
			return ErrInvalidAppManifest
		}
		if _, err := directory.file.Seek(0, io.SeekStart); err != nil {
			return ErrInvalidAppManifest
		}
		sort.Slice(entries, func(left, right int) bool {
			return bytes.Compare(
				[]byte(entries[left].Name()),
				[]byte(entries[right].Name()),
			) < 0
		})
		for _, entry := range entries {
			if len(result) >= maximumCanonicalAppEntries ||
				!fixedCanonicalBaseName(entry.Name()) ||
				entry.Type()&os.ModeSymlink != 0 {
				return ErrInvalidAppManifest
			}
			relative := entry.Name()
			if prefix != "" {
				relative = prefix + "/" + entry.Name()
			}
			if entry.IsDir() {
				child, err := openCanonicalTreeChild(
					directory,
					entry.Name(),
				)
				if err != nil {
					return err
				}
				result = append(result, canonicalAppTreeEntry{
					RelativePath: relative,
					Type:         "directory",
					Mode:         "0755",
					ByteLength:   0,
					SHA256:       nil,
				})
				visitErr := visit(child, relative, depth+1)
				closeErr := child.close()
				if visitErr != nil || closeErr != nil {
					return ErrInvalidAppManifest
				}
				continue
			}
			if !entry.Type().IsRegular() {
				return ErrInvalidAppManifest
			}
			item, err := hashCanonicalAppFile(
				directory,
				entry.Name(),
				relative,
			)
			if err != nil {
				return err
			}
			result = append(result, item)
		}
		return directory.revalidate()
	}
	if err := visit(root, "", 0); err != nil || len(result) <= 1 {
		return nil, ErrInvalidAppManifest
	}
	return result, nil
}

func hashCanonicalAppFile(
	parent *canonicalTreeDirectory,
	name string,
	relative string,
) (canonicalAppTreeEntry, error) {
	if parent == nil ||
		parent.revalidate() != nil ||
		!fixedCanonicalBaseName(name) ||
		!validCanonicalAppRelativePath(relative) {
		return canonicalAppTreeEntry{}, ErrInvalidAppManifest
	}
	fd, err := unix.Openat(
		int(parent.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return canonicalAppTreeEntry{}, ErrInvalidAppManifest
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return canonicalAppTreeEntry{}, ErrInvalidAppManifest
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil ||
		!before.Mode().IsRegular() ||
		before.Mode()&os.ModeSymlink != 0 ||
		(before.Mode().Perm() != 0o644 &&
			before.Mode().Perm() != 0o755) ||
		before.Size() < 0 ||
		before.Size() > maximumCanonicalAppFileSize {
		return canonicalAppTreeEntry{}, ErrInvalidAppManifest
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok ||
		stat.Uid != parent.uid ||
		stat.Gid != parent.gid ||
		stat.Nlink != 1 {
		return canonicalAppTreeEntry{}, ErrInvalidAppManifest
	}
	hasher := sha256.New()
	read, err := io.Copy(
		hasher,
		io.LimitReader(file, maximumCanonicalAppFileSize+1),
	)
	if err != nil || read != before.Size() {
		return canonicalAppTreeEntry{}, ErrInvalidAppManifest
	}
	after, afterErr := file.Stat()
	pathInfo, pathErr := os.Lstat(filepath.Join(parent.path, name))
	if afterErr != nil ||
		pathErr != nil ||
		!os.SameFile(before, after) ||
		!os.SameFile(after, pathInfo) ||
		!before.ModTime().Equal(after.ModTime()) ||
		!after.ModTime().Equal(pathInfo.ModTime()) ||
		parent.revalidate() != nil {
		return canonicalAppTreeEntry{}, ErrInvalidAppManifest
	}
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	pathStat, pathOK := pathInfo.Sys().(*syscall.Stat_t)
	if !afterOK ||
		!pathOK ||
		afterStat.Uid != stat.Uid ||
		afterStat.Gid != stat.Gid ||
		afterStat.Nlink != stat.Nlink ||
		pathStat.Uid != stat.Uid ||
		pathStat.Gid != stat.Gid ||
		pathStat.Nlink != stat.Nlink ||
		after.Mode() != before.Mode() ||
		pathInfo.Mode() != before.Mode() ||
		after.Size() != before.Size() ||
		pathInfo.Size() != before.Size() {
		return canonicalAppTreeEntry{}, ErrInvalidAppManifest
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	return canonicalAppTreeEntry{
		RelativePath: relative,
		Type:         "file",
		Mode:         fmt.Sprintf("%04o", before.Mode().Perm()),
		ByteLength:   uint64(read),
		SHA256:       &digest,
	}, nil
}

func equalCanonicalAppTreeEntry(
	left canonicalAppTreeEntry,
	right canonicalAppTreeEntry,
) bool {
	if left.RelativePath != right.RelativePath ||
		left.Type != right.Type ||
		left.Mode != right.Mode ||
		left.ByteLength != right.ByteLength ||
		(left.SHA256 == nil) != (right.SHA256 == nil) {
		return false
	}
	return left.SHA256 == nil || *left.SHA256 == *right.SHA256
}

func fixedCanonicalBaseName(value string) bool {
	return value != "" &&
		value != "." &&
		value != ".." &&
		filepath.Base(value) == value &&
		!strings.ContainsAny(value, `/\`+"\x00")
}
