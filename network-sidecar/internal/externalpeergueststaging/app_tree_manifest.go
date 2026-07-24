package externalpeergueststaging

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	AppTreeManifestInputName = "app-tree-manifest.json"
	maximumAppManifestSize   = 4 * 1024 * 1024
)

type appBuildSource struct {
	Commit       string `json:"commit"`
	Dirty        bool   `json:"dirty"`
	StatusSHA256 string `json:"status_sha256"`
	TreeSHA256   string `json:"tree_sha256"`
	FileCount    int    `json:"file_count"`
}

type appInfoPlistRecord struct {
	RelativePath     string `json:"relative_path"`
	BundleIdentifier string `json:"bundle_identifier"`
	ShortVersion     string `json:"short_version"`
	BundleVersion    string `json:"bundle_version"`
	BundleExecutable string `json:"bundle_executable"`
}

type appExecutableRecord struct {
	RelativePath string `json:"relative_path"`
	Mode         string `json:"mode"`
	ByteLength   uint64 `json:"byte_length"`
	SHA256       string `json:"sha256"`
}

type appTreeEntry struct {
	RelativePath string  `json:"relative_path"`
	Type         string  `json:"type"`
	Mode         string  `json:"mode"`
	ByteLength   uint64  `json:"byte_length"`
	SHA256       *string `json:"sha256"`
}

type appTreeManifest struct {
	SchemaVersion  uint8               `json:"schema_version"`
	AppName        string              `json:"app_name"`
	Source         appBuildSource      `json:"source"`
	TreeSHA256     string              `json:"tree_sha256"`
	InfoPlist      appInfoPlistRecord  `json:"info_plist"`
	MainExecutable appExecutableRecord `json:"main_executable"`
	Entries        []appTreeEntry      `json:"entries"`
}

func decodeAppTreeManifest(data []byte) (appTreeManifest, error) {
	if len(data) == 0 ||
		len(data) > maximumAppManifestSize ||
		rejectDuplicateJSONKeys(data) != nil {
		return appTreeManifest{}, ErrGuestStaging
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest appTreeManifest
	if decoder.Decode(&manifest) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		manifest.validate() != nil {
		return appTreeManifest{}, ErrGuestStaging
	}
	return manifest, nil
}

func (manifest appTreeManifest) validate() error {
	if manifest.SchemaVersion != 1 ||
		manifest.AppName != AppInputName ||
		len(manifest.Source.Commit) != 40 ||
		!validLowerHexDigest(manifest.Source.Commit) ||
		!validLowerSHA256Digest(manifest.Source.StatusSHA256) ||
		!validLowerSHA256Digest(manifest.Source.TreeSHA256) ||
		manifest.Source.FileCount <= 0 ||
		!validLowerSHA256Digest(manifest.TreeSHA256) ||
		manifest.InfoPlist.RelativePath != "Contents/Info.plist" ||
		manifest.InfoPlist.BundleIdentifier != "net.kysion.kyclash" ||
		manifest.InfoPlist.BundleExecutable != "clash-verge" ||
		!validManifestString(manifest.InfoPlist.ShortVersion) ||
		!validManifestString(manifest.InfoPlist.BundleVersion) ||
		manifest.MainExecutable.RelativePath !=
			"Contents/MacOS/clash-verge" ||
		manifest.MainExecutable.Mode != "0755" ||
		manifest.MainExecutable.ByteLength < 32 ||
		manifest.MainExecutable.ByteLength > maximumAppFileSize ||
		!validLowerSHA256Digest(manifest.MainExecutable.SHA256) ||
		len(manifest.Entries) == 0 ||
		len(manifest.Entries) > maximumAppEntries {
		return ErrGuestStaging
	}
	encodedEntries, err := json.Marshal(manifest.Entries)
	if err != nil || hashHex(encodedEntries) != manifest.TreeSHA256 {
		return ErrGuestStaging
	}
	parents := map[string]struct{}{".": {}}
	previous := ""
	var infoEntry *appTreeEntry
	var executableEntry *appTreeEntry
	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		if !validAppRelativePath(entry.RelativePath) ||
			index > 0 &&
				bytes.Compare(
					[]byte(previous),
					[]byte(entry.RelativePath),
				) >= 0 ||
			(entry.Type != "directory" && entry.Type != "file") ||
			!validCanonicalAppMode(entry.Mode) {
			return ErrGuestStaging
		}
		if index == 0 {
			if entry.RelativePath != "." ||
				entry.Type != "directory" ||
				entry.Mode != "0755" {
				return ErrGuestStaging
			}
		} else {
			parent := filepath.Dir(entry.RelativePath)
			if parent == "." {
				parent = "."
			}
			if _, exists := parents[parent]; !exists {
				return ErrGuestStaging
			}
		}
		if entry.Type == "directory" {
			if entry.Mode != "0755" ||
				entry.ByteLength != 0 ||
				entry.SHA256 != nil {
				return ErrGuestStaging
			}
			parents[entry.RelativePath] = struct{}{}
		} else if entry.SHA256 == nil ||
			entry.ByteLength > maximumAppFileSize ||
			!validLowerSHA256Digest(*entry.SHA256) {
			return ErrGuestStaging
		}
		if entry.RelativePath == manifest.InfoPlist.RelativePath {
			infoEntry = entry
		}
		if entry.RelativePath == manifest.MainExecutable.RelativePath {
			executableEntry = entry
		}
		previous = entry.RelativePath
	}
	if infoEntry == nil ||
		infoEntry.Type != "file" ||
		infoEntry.Mode != "0644" ||
		executableEntry == nil ||
		executableEntry.Type != "file" ||
		executableEntry.Mode != manifest.MainExecutable.Mode ||
		executableEntry.ByteLength != manifest.MainExecutable.ByteLength ||
		executableEntry.SHA256 == nil ||
		*executableEntry.SHA256 != manifest.MainExecutable.SHA256 {
		return ErrGuestStaging
	}
	return nil
}

func validManifestString(value string) bool {
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

func validAppRelativePath(value string) bool {
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

func validLowerHexDigest(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return value != ""
}

func validLowerSHA256Digest(value string) bool {
	return len(value) == sha256.Size*2 && validLowerHexDigest(value)
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var readValue func() error
	readValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return ErrGuestStaging
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
					return ErrGuestStaging
				}
				if _, exists := seen[key]; exists {
					return ErrGuestStaging
				}
				seen[key] = struct{}{}
				if err := readValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrGuestStaging
			}
		case '[':
			for decoder.More() {
				if err := readValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return ErrGuestStaging
			}
		default:
			return ErrGuestStaging
		}
		return nil
	}
	if readValue() != nil {
		return ErrGuestStaging
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return ErrGuestStaging
	}
	return nil
}

func verifyStableAppTree(
	root *stableDirectory,
	manifest appTreeManifest,
	expectedRootMode os.FileMode,
) error {
	actual, err := collectStableAppTree(root)
	if err != nil ||
		root.mode != expectedRootMode.Perm() ||
		len(actual) != len(manifest.Entries) {
		return ErrGuestStaging
	}
	for index := range actual {
		if index == 0 && expectedRootMode.Perm() == inputDirectoryMode {
			actual[index].Mode = manifest.Entries[index].Mode
		}
		if !equalAppTreeEntry(actual[index], manifest.Entries[index]) {
			return ErrGuestStaging
		}
	}
	encoded, err := json.Marshal(actual)
	if err != nil || hashHex(encoded) != manifest.TreeSHA256 {
		return ErrGuestStaging
	}
	return root.revalidate()
}

func collectStableAppTree(
	root *stableDirectory,
) ([]appTreeEntry, error) {
	if root == nil ||
		root.revalidate() != nil ||
		(root.mode != 0o755 && root.mode != inputDirectoryMode) {
		return nil, ErrGuestStaging
	}
	result := []appTreeEntry{{
		RelativePath: ".",
		Type:         "directory",
		Mode:         fmt.Sprintf("%04o", root.mode),
		ByteLength:   0,
		SHA256:       nil,
	}}
	var visit func(*stableDirectory, string, int) error
	visit = func(
		directory *stableDirectory,
		prefix string,
		depth int,
	) error {
		if depth > maximumAppDepth || directory.revalidate() != nil {
			return ErrGuestStaging
		}
		entries, err := directory.file.ReadDir(-1)
		if err != nil {
			return ErrGuestStaging
		}
		if _, err := directory.file.Seek(0, io.SeekStart); err != nil {
			return ErrGuestStaging
		}
		sort.Slice(entries, func(left, right int) bool {
			return bytes.Compare(
				[]byte(entries[left].Name()),
				[]byte(entries[right].Name()),
			) < 0
		})
		for _, entry := range entries {
			if len(result) >= maximumAppEntries ||
				!fixedBaseName(entry.Name()) ||
				entry.Type()&os.ModeSymlink != 0 {
				return ErrGuestStaging
			}
			relative := entry.Name()
			if prefix != "" {
				relative = prefix + "/" + entry.Name()
			}
			if entry.IsDir() {
				child, err := openStableAppDirectory(
					directory,
					entry.Name(),
				)
				if err != nil || child.mode != 0o755 {
					if child != nil {
						_ = child.close()
					}
					return ErrGuestStaging
				}
				result = append(result, appTreeEntry{
					RelativePath: relative,
					Type:         "directory",
					Mode:         "0755",
					ByteLength:   0,
					SHA256:       nil,
				})
				visitErr := visit(child, relative, depth+1)
				closeErr := child.close()
				if visitErr != nil || closeErr != nil {
					return ErrGuestStaging
				}
				continue
			}
			if !entry.Type().IsRegular() {
				return ErrGuestStaging
			}
			item, err := hashStableAppFile(
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
	if err := visit(root, "", 0); err != nil ||
		len(result) <= 1 ||
		len(result) > maximumAppEntries {
		return nil, ErrGuestStaging
	}
	return result, nil
}

func hashStableAppFile(
	parent *stableDirectory,
	name string,
	relative string,
) (appTreeEntry, error) {
	if parent == nil ||
		parent.revalidate() != nil ||
		!fixedBaseName(name) ||
		!validAppRelativePath(relative) {
		return appTreeEntry{}, ErrGuestStaging
	}
	fd, err := unix.Openat(
		int(parent.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return appTreeEntry{}, ErrGuestStaging
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return appTreeEntry{}, ErrGuestStaging
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil ||
		!before.Mode().IsRegular() ||
		before.Mode()&os.ModeSymlink != 0 ||
		(before.Mode().Perm() != 0o644 &&
			before.Mode().Perm() != 0o755) ||
		before.Size() < 0 ||
		before.Size() > maximumAppFileSize {
		return appTreeEntry{}, ErrGuestStaging
	}
	beforeID, err := identityFromInfo(before)
	if err != nil ||
		beforeID.UID != parent.uid ||
		beforeID.GID != parent.gid ||
		beforeID.Links != 1 {
		return appTreeEntry{}, ErrGuestStaging
	}
	hasher := sha256.New()
	read, err := io.Copy(
		hasher,
		io.LimitReader(file, maximumAppFileSize+1),
	)
	if err != nil || read != before.Size() {
		return appTreeEntry{}, ErrGuestStaging
	}
	after, afterErr := file.Stat()
	pathInfo, pathErr := os.Lstat(filepath.Join(parent.path, name))
	afterID, afterIdentityErr := identityFromInfo(after)
	pathID, pathIdentityErr := identityFromInfo(pathInfo)
	if afterErr != nil ||
		pathErr != nil ||
		afterIdentityErr != nil ||
		pathIdentityErr != nil ||
		beforeID != afterID ||
		afterID != pathID ||
		!os.SameFile(before, after) ||
		!os.SameFile(after, pathInfo) ||
		parent.revalidate() != nil {
		return appTreeEntry{}, ErrGuestStaging
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	return appTreeEntry{
		RelativePath: relative,
		Type:         "file",
		Mode:         fmt.Sprintf("%04o", before.Mode().Perm()),
		ByteLength:   uint64(read),
		SHA256:       &digest,
	}, nil
}

func equalAppTreeEntry(left appTreeEntry, right appTreeEntry) bool {
	if left.RelativePath != right.RelativePath ||
		left.Type != right.Type ||
		left.Mode != right.Mode ||
		left.ByteLength != right.ByteLength ||
		(left.SHA256 == nil) != (right.SHA256 == nil) {
		return false
	}
	return left.SHA256 == nil || *left.SHA256 == *right.SHA256
}
