//go:build linux

package productionpeer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	binaryIdentityPeerUIDForTest   uint32 = 64210
	binaryIdentityBrokerUIDForTest uint32 = 64211
	binaryIdentityIPCGIDForTest    uint32 = 64212
)

type binaryIdentityFakeNodeV1 struct {
	name         string
	facts        unix.Statx_t
	accessACL    binaryIdentityXattrV1
	defaultACL   binaryIdentityXattrV1
	capabilities binaryIdentityXattrV1
	data         []byte
	children     map[string]*binaryIdentityFakeNodeV1
}

type binaryIdentityFakeOpenatCallV1 struct {
	parent string
	path   string
	how    unix.OpenHow
}

type binaryIdentityFakeFilesystemV1 struct {
	nextDescriptor int
	root           *binaryIdentityFakeNodeV1
	descriptors    map[int]*binaryIdentityFakeNodeV1
	openCalls      []int
	openatCalls    []binaryIdentityFakeOpenatCallV1
	closeCalls     int
	readCalls      map[string]int

	rejectOpenName    string
	rejectReadName    string
	rejectXattrName   string
	rejectXattrError  error
	afterFirstRead    func(*binaryIdentityFakeFilesystemV1, *binaryIdentityFakeNodeV1)
	afterFirstReadFor string
	readHookUsed      bool
}

func (fixture *binaryIdentityFakeFilesystemV1) allocateDescriptor(
	node *binaryIdentityFakeNodeV1,
) int {
	descriptor := fixture.nextDescriptor
	fixture.nextDescriptor++
	fixture.descriptors[descriptor] = node
	return descriptor
}

func (fixture *binaryIdentityFakeFilesystemV1) open(
	path string,
	flags int,
	_ uint32,
) (int, error) {
	if path != "/" ||
		(flags != binaryIdentityDirectoryPathFlagsV1() &&
			flags != binaryIdentityDirectoryDataFlagsV1()) {
		return -1, unix.EINVAL
	}
	fixture.openCalls = append(fixture.openCalls, flags)
	return fixture.allocateDescriptor(fixture.root), nil
}

func (fixture *binaryIdentityFakeFilesystemV1) openat2(
	directoryDescriptor int,
	path string,
	how *unix.OpenHow,
) (int, error) {
	parent := fixture.descriptors[directoryDescriptor]
	if parent == nil ||
		how == nil ||
		how.Resolve != binaryIdentityResolveFlagsV1() ||
		!validBinaryIdentityPathComponentV1(path) ||
		(how.Flags != uint64(binaryIdentityDirectoryPathFlagsV1()) &&
			how.Flags != uint64(binaryIdentityDirectoryDataFlagsV1()) &&
			how.Flags != uint64(binaryIdentityFilePathFlagsV1()) &&
			how.Flags != uint64(binaryIdentityFileDataFlagsV1())) {
		return -1, unix.EINVAL
	}
	fixture.openatCalls = append(fixture.openatCalls, binaryIdentityFakeOpenatCallV1{
		parent: parent.name,
		path:   path,
		how:    *how,
	})
	if path == fixture.rejectOpenName {
		return -1, unix.ELOOP
	}
	child := parent.children[path]
	if child == nil {
		return -1, unix.ENOENT
	}
	return fixture.allocateDescriptor(child), nil
}

func (fixture *binaryIdentityFakeFilesystemV1) close(descriptor int) error {
	if fixture.descriptors[descriptor] == nil {
		return unix.EBADF
	}
	delete(fixture.descriptors, descriptor)
	fixture.closeCalls++
	return nil
}

func (fixture *binaryIdentityFakeFilesystemV1) statx(
	directoryDescriptor int,
	path string,
	flags int,
	mask int,
	facts *unix.Statx_t,
) error {
	parent := fixture.descriptors[directoryDescriptor]
	if parent == nil || facts == nil || mask != binaryIdentityStatxMaskV1() {
		return unix.EINVAL
	}
	var node *binaryIdentityFakeNodeV1
	switch {
	case path == "" && flags == unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW:
		node = parent
	case validBinaryIdentityPathComponentV1(path) && flags == unix.AT_SYMLINK_NOFOLLOW:
		node = parent.children[path]
	default:
		return unix.EINVAL
	}
	if node == nil {
		return unix.ENOENT
	}
	*facts = node.facts
	return nil
}

func (fixture *binaryIdentityFakeFilesystemV1) readXattr(
	descriptor int,
	name string,
) (binaryIdentityXattrV1, error) {
	node := fixture.descriptors[descriptor]
	if node == nil {
		return binaryIdentityXattrV1{}, unix.EBADF
	}
	if node.name == fixture.rejectXattrName && fixture.rejectXattrError != nil {
		return binaryIdentityXattrV1{}, fixture.rejectXattrError
	}
	switch name {
	case binaryIdentityACLAccessXattrV1:
		return cloneBinaryIdentityXattrForTest(node.accessACL), nil
	case binaryIdentityACLDefaultXattrV1:
		return cloneBinaryIdentityXattrForTest(node.defaultACL), nil
	case binaryIdentityCapabilityXattrV1:
		return cloneBinaryIdentityXattrForTest(node.capabilities), nil
	default:
		return binaryIdentityXattrV1{}, unix.ENODATA
	}
}

func (fixture *binaryIdentityFakeFilesystemV1) pread(
	descriptor int,
	destination []byte,
	offset int64,
) (int, error) {
	node := fixture.descriptors[descriptor]
	if node == nil || offset < 0 {
		return 0, unix.EBADF
	}
	if node.name == fixture.rejectReadName {
		return 0, unix.EIO
	}
	fixture.readCalls[node.name]++
	if offset >= int64(len(node.data)) {
		return 0, nil
	}
	count := copy(destination, node.data[offset:])
	if count > 0 &&
		!fixture.readHookUsed &&
		node.name == fixture.afterFirstReadFor &&
		fixture.afterFirstRead != nil {
		fixture.readHookUsed = true
		fixture.afterFirstRead(fixture, node)
	}
	return count, nil
}

func newBinaryIdentityFakeFilesystemV1(t *testing.T) *binaryIdentityFakeFilesystemV1 {
	t.Helper()

	fixture := &binaryIdentityFakeFilesystemV1{
		nextDescriptor: 100,
		descriptors:    make(map[int]*binaryIdentityFakeNodeV1),
		readCalls:      make(map[string]int),
	}
	inode := uint64(40)
	newDirectory := func(name string) *binaryIdentityFakeNodeV1 {
		node := &binaryIdentityFakeNodeV1{
			name:     name,
			facts:    binaryIdentityRawFactsForTest(unix.S_IFDIR|0o755, 0, 0, 4096, 2, inode),
			children: make(map[string]*binaryIdentityFakeNodeV1),
		}
		inode++
		return node
	}
	newFile := func(name string, mode uint16, data []byte) *binaryIdentityFakeNodeV1 {
		node := &binaryIdentityFakeNodeV1{
			name:  name,
			facts: binaryIdentityRawFactsForTest(mode, 0, 0, uint64(len(data)), 1, inode),
			data:  bytes.Clone(data),
		}
		inode++
		return node
	}

	root := newDirectory("/")
	usr := newDirectory("usr")
	lib := newDirectory("lib")
	manifestDirectory := newDirectory("kyclash")
	executableDirectory := newDirectory("libexec")
	root.children["usr"] = usr
	usr.children["lib"] = lib
	usr.children["libexec"] = executableDirectory
	lib.children["kyclash"] = manifestDirectory
	fixture.root = root

	peerData := []byte("synthetic-peer-binary-v1")
	brokerData := []byte("synthetic-broker-binary-v1")
	bootstrapData := []byte("synthetic-host-bootstrap-binary-v1")
	peerDigest := sha256.Sum256(peerData)
	brokerDigest := sha256.Sum256(brokerData)
	bootstrapDigest := sha256.Sum256(bootstrapData)
	wire := binaryIdentityManifestJSONV1{
		SchemaVersion: binaryIdentityManifestSchemaVersionV1,
		PeerUID:       binaryIdentityPeerUIDForTest,
		BrokerUID:     binaryIdentityBrokerUIDForTest,
		IPCGID:        binaryIdentityIPCGIDForTest,
		Binaries: binaryIdentityManifestBinariesJSONV1{
			PeerSHA256:          hex.EncodeToString(peerDigest[:]),
			BrokerSHA256:        hex.EncodeToString(brokerDigest[:]),
			HostBootstrapSHA256: hex.EncodeToString(bootstrapDigest[:]),
		},
	}
	manifestData, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("encode binary identity fixture: %v", err)
	}
	manifestDirectory.children[binaryIdentityManifestFileNameV1] = newFile(
		binaryIdentityManifestFileNameV1,
		binaryIdentityManifestModeV1,
		manifestData,
	)
	executableDirectory.children[binaryIdentityPeerFileNameV1] = newFile(
		binaryIdentityPeerFileNameV1,
		binaryIdentityExecutableModeV1,
		peerData,
	)
	executableDirectory.children[binaryIdentityBrokerFileNameV1] = newFile(
		binaryIdentityBrokerFileNameV1,
		binaryIdentityExecutableModeV1,
		brokerData,
	)
	executableDirectory.children[binaryIdentityBootstrapFileNameV1] = newFile(
		binaryIdentityBootstrapFileNameV1,
		binaryIdentityExecutableModeV1,
		bootstrapData,
	)
	return fixture
}

func binaryIdentityRawFactsForTest(
	mode uint16,
	uid uint32,
	gid uint32,
	size uint64,
	nlink uint32,
	inode uint64,
) unix.Statx_t {
	return unix.Statx_t{
		Mask:            uint32(binaryIdentityStatxMaskV1()),
		Attributes:      0,
		Attributes_mask: 0x003fff,
		Nlink:           nlink,
		Uid:             uid,
		Gid:             gid,
		Mode:            mode,
		Ino:             inode,
		Size:            size,
		Blocks:          1,
		Ctime:           unix.StatxTimestamp{Sec: 100, Nsec: uint32(inode)},
		Mtime:           unix.StatxTimestamp{Sec: 90, Nsec: uint32(inode)},
		Dev_major:       0,
		Dev_minor:       27,
		Mnt_id:          73,
	}
}

func cloneBinaryIdentityXattrForTest(
	attribute binaryIdentityXattrV1,
) binaryIdentityXattrV1 {
	return binaryIdentityXattrV1{
		present: attribute.present,
		encoded: bytes.Clone(attribute.encoded),
	}
}

func binaryIdentityNodeForTest(
	fixture *binaryIdentityFakeFilesystemV1,
	components ...string,
) *binaryIdentityFakeNodeV1 {
	node := fixture.root
	for _, component := range components {
		if node == nil {
			return nil
		}
		node = node.children[component]
	}
	return node
}

func cloneBinaryIdentityNodeForTest(
	node *binaryIdentityFakeNodeV1,
) *binaryIdentityFakeNodeV1 {
	if node == nil {
		return nil
	}
	clone := &binaryIdentityFakeNodeV1{
		name:         node.name,
		facts:        node.facts,
		accessACL:    cloneBinaryIdentityXattrForTest(node.accessACL),
		defaultACL:   cloneBinaryIdentityXattrForTest(node.defaultACL),
		capabilities: cloneBinaryIdentityXattrForTest(node.capabilities),
		data:         bytes.Clone(node.data),
		children:     make(map[string]*binaryIdentityFakeNodeV1, len(node.children)),
	}
	for name, child := range node.children {
		clone.children[name] = child
	}
	return clone
}

func requireBinaryIdentityFilesystemRejectedForTest(
	t *testing.T,
	fixture *binaryIdentityFakeFilesystemV1,
) {
	t.Helper()
	manifest, err := validateFixedBinaryIdentityFilesystemV1WithOps(fixture)
	if !errors.Is(err, errBinaryIdentityManifestUnavailableV1) ||
		manifest != (binaryIdentityManifestV1{}) {
		t.Fatalf("unsafe filesystem escaped: manifest=%#v err=%v", manifest, err)
	}
	if len(fixture.descriptors) != 0 {
		t.Fatalf("failed transaction leaked descriptors: %v", fixture.descriptors)
	}
}

func requireBinaryIdentityOpenatSequenceForTest(
	t *testing.T,
	actual []binaryIdentityFakeOpenatCallV1,
) {
	t.Helper()
	pathDirectory := uint64(binaryIdentityDirectoryPathFlagsV1())
	dataDirectory := uint64(binaryIdentityDirectoryDataFlagsV1())
	pathFile := uint64(binaryIdentityFilePathFlagsV1())
	dataFile := uint64(binaryIdentityFileDataFlagsV1())
	type expectedCall struct {
		parent string
		path   string
		flags  uint64
	}
	pair := func(parent string, path string, pathFlags uint64, dataFlags uint64) []expectedCall {
		return []expectedCall{
			{parent: parent, path: path, flags: pathFlags},
			{parent: parent, path: path, flags: dataFlags},
		}
	}
	expected := make([]expectedCall, 0, 32)
	expected = append(expected, pair("/", "usr", pathDirectory, dataDirectory)...)
	expected = append(expected, pair("usr", "lib", pathDirectory, dataDirectory)...)
	expected = append(expected, pair("lib", "kyclash", pathDirectory, dataDirectory)...)
	expected = append(expected, pair("usr", "libexec", pathDirectory, dataDirectory)...)
	expected = append(expected, pair("kyclash", binaryIdentityManifestFileNameV1, pathFile, dataFile)...)
	for _, name := range binaryIdentityExecutableNamesV1 {
		expected = append(expected, pair("libexec", name, pathFile, dataFile)...)
	}
	expected = append(expected, pair("kyclash", binaryIdentityManifestFileNameV1, pathFile, dataFile)...)
	for _, name := range binaryIdentityExecutableNamesV1 {
		expected = append(expected, pair("libexec", name, pathFile, dataFile)...)
	}
	expected = append(expected, pair("usr", "libexec", pathDirectory, dataDirectory)...)
	expected = append(expected, pair("lib", "kyclash", pathDirectory, dataDirectory)...)
	expected = append(expected, pair("usr", "lib", pathDirectory, dataDirectory)...)
	expected = append(expected, pair("/", "usr", pathDirectory, dataDirectory)...)

	if len(actual) != len(expected) {
		t.Fatalf("unexpected openat2 call count: got=%d want=%d calls=%#v", len(actual), len(expected), actual)
	}
	for index, want := range expected {
		got := actual[index]
		if got.parent != want.parent ||
			got.path != want.path ||
			got.how.Flags != want.flags ||
			got.how.Mode != 0 ||
			got.how.Resolve != binaryIdentityResolveFlagsV1() {
			t.Fatalf("openat2 call %d drifted: got=%#v want=%#v", index, got, want)
		}
	}
}

func TestFixedBinaryIdentityFilesystemV1AcceptsExactClosedFixture(t *testing.T) {
	t.Parallel()

	fixture := newBinaryIdentityFakeFilesystemV1(t)
	expectedManifestDigest := sha256.Sum256(
		binaryIdentityNodeForTest(
			fixture,
			"usr",
			"lib",
			"kyclash",
			binaryIdentityManifestFileNameV1,
		).data,
	)
	manifest, err := validateFixedBinaryIdentityFilesystemV1WithOps(fixture)
	if err != nil {
		t.Fatalf("exact fixed binary identity filesystem was rejected: %v", err)
	}
	if manifest.peerUID != binaryIdentityPeerUIDForTest ||
		manifest.brokerUID != binaryIdentityBrokerUIDForTest ||
		manifest.ipcGID != binaryIdentityIPCGIDForTest ||
		manifest.manifestSHA256 != expectedManifestDigest {
		t.Fatalf("unexpected manifest identity facts: %#v", manifest)
	}
	if len(fixture.descriptors) != 0 {
		t.Fatalf("successful transaction leaked descriptors: %v", fixture.descriptors)
	}
	expectedRootOpens := []int{
		binaryIdentityDirectoryPathFlagsV1(),
		binaryIdentityDirectoryDataFlagsV1(),
		binaryIdentityDirectoryPathFlagsV1(),
		binaryIdentityDirectoryDataFlagsV1(),
	}
	if !slices.Equal(fixture.openCalls, expectedRootOpens) {
		t.Fatalf("root open sequence drifted: got=%v want=%v", fixture.openCalls, expectedRootOpens)
	}
	for _, call := range fixture.openatCalls {
		if !validBinaryIdentityPathComponentV1(call.path) {
			t.Fatalf("non-component or caller-selected path reached openat2: %#v", call)
		}
	}
	for _, name := range []string{
		binaryIdentityManifestFileNameV1,
		binaryIdentityPeerFileNameV1,
		binaryIdentityBrokerFileNameV1,
		binaryIdentityBootstrapFileNameV1,
	} {
		if fixture.readCalls[name] != 4 {
			t.Fatalf("%s did not have exactly two reads and two EOF probes: %d", name, fixture.readCalls[name])
		}
	}
	requireBinaryIdentityOpenatSequenceForTest(t, fixture.openatCalls)
}

func TestFixedBinaryIdentityFilesystemV1PinsReviewedAbsolutePaths(t *testing.T) {
	t.Parallel()

	if binaryIdentityManifestDirectoryV1+"/"+binaryIdentityManifestFileNameV1 !=
		binaryIdentityManifestPathV1 ||
		binaryIdentityExecutableDirectory+"/"+binaryIdentityPeerFileNameV1 !=
			binaryIdentityPeerPathV1 ||
		binaryIdentityExecutableDirectory+"/"+binaryIdentityBrokerFileNameV1 !=
			binaryIdentityBrokerPathV1 ||
		binaryIdentityExecutableDirectory+"/"+binaryIdentityBootstrapFileNameV1 !=
			binaryIdentityBootstrapPathV1 {
		t.Fatal("fixed binary identity path contract drifted")
	}
}

func TestFixedBinaryIdentityFilesystemV1RejectsUnsafeFilesAndDirectories(t *testing.T) {
	t.Parallel()

	type mutation func(*binaryIdentityFakeFilesystemV1)
	cases := map[string]mutation{
		"nil operations": nil,
		"missing manifest": func(fixture *binaryIdentityFakeFilesystemV1) {
			delete(binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash").children, binaryIdentityManifestFileNameV1)
		},
		"symlink manifest": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash", binaryIdentityManifestFileNameV1).facts.Mode = unix.S_IFLNK | 0o777
		},
		"manifest owner": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash", binaryIdentityManifestFileNameV1).facts.Uid = binaryIdentityPeerUIDForTest
		},
		"manifest group": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash", binaryIdentityManifestFileNameV1).facts.Gid = binaryIdentityIPCGIDForTest
		},
		"manifest mode": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash", binaryIdentityManifestFileNameV1).facts.Mode = unix.S_IFREG | 0o664
		},
		"manifest hardlink": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash", binaryIdentityManifestFileNameV1).facts.Nlink = 2
		},
		"manifest empty": func(fixture *binaryIdentityFakeFilesystemV1) {
			node := binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash", binaryIdentityManifestFileNameV1)
			node.data = nil
			node.facts.Size = 0
		},
		"manifest oversized": func(fixture *binaryIdentityFakeFilesystemV1) {
			node := binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash", binaryIdentityManifestFileNameV1)
			node.data = bytes.Repeat([]byte{'x'}, binaryIdentityManifestMaxSizeV1+1)
			node.facts.Size = uint64(len(node.data))
		},
		"manifest access ACL": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash", binaryIdentityManifestFileNameV1).accessACL = binaryIdentityXattrV1{present: true, encoded: []byte{1}}
		},
		"manifest default ACL": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash", binaryIdentityManifestFileNameV1).defaultACL = binaryIdentityXattrV1{present: true, encoded: []byte{1}}
		},
		"manifest capability": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash", binaryIdentityManifestFileNameV1).capabilities = binaryIdentityXattrV1{present: true, encoded: []byte{1}}
		},
		"peer owner": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "libexec", binaryIdentityPeerFileNameV1).facts.Uid = binaryIdentityPeerUIDForTest
		},
		"peer group": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "libexec", binaryIdentityPeerFileNameV1).facts.Gid = binaryIdentityIPCGIDForTest
		},
		"peer mode": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "libexec", binaryIdentityPeerFileNameV1).facts.Mode = unix.S_IFREG | 0o775
		},
		"broker hardlink": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "libexec", binaryIdentityBrokerFileNameV1).facts.Nlink = 2
		},
		"bootstrap capability": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "libexec", binaryIdentityBootstrapFileNameV1).capabilities = binaryIdentityXattrV1{present: true, encoded: []byte{1}}
		},
		"bootstrap ACL": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "libexec", binaryIdentityBootstrapFileNameV1).accessACL = binaryIdentityXattrV1{present: true, encoded: []byte{1}}
		},
		"world writable usr": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr").facts.Mode = unix.S_IFDIR | 0o757
		},
		"nonroot lib": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "lib").facts.Uid = 1
		},
		"wrong-group manifest directory": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash").facts.Gid = 1
		},
		"libexec ACL": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "libexec").defaultACL = binaryIdentityXattrV1{present: true, encoded: []byte{1}}
		},
		"root capability": func(fixture *binaryIdentityFakeFilesystemV1) {
			fixture.root.capabilities = binaryIdentityXattrV1{present: true, encoded: []byte{1}}
		},
		"incomplete statx": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "libexec", binaryIdentityPeerFileNameV1).facts.Mask &^= unix.STATX_MNT_ID
		},
		"zero mount id": func(fixture *binaryIdentityFakeFilesystemV1) {
			binaryIdentityNodeForTest(fixture, "usr", "libexec", binaryIdentityPeerFileNameV1).facts.Mnt_id = 0
		},
		"malformed manifest": func(fixture *binaryIdentityFakeFilesystemV1) {
			node := binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash", binaryIdentityManifestFileNameV1)
			node.data = []byte(`{}`)
			node.facts.Size = uint64(len(node.data))
		},
		"digest mismatch": func(fixture *binaryIdentityFakeFilesystemV1) {
			node := binaryIdentityNodeForTest(fixture, "usr", "libexec", binaryIdentityPeerFileNameV1)
			node.data[0] ^= 1
		},
		"open refusal": func(fixture *binaryIdentityFakeFilesystemV1) {
			fixture.rejectOpenName = binaryIdentityBrokerFileNameV1
		},
		"read refusal": func(fixture *binaryIdentityFakeFilesystemV1) {
			fixture.rejectReadName = binaryIdentityBootstrapFileNameV1
		},
		"xattr unsupported": func(fixture *binaryIdentityFakeFilesystemV1) {
			fixture.rejectXattrName = binaryIdentityPeerFileNameV1
			fixture.rejectXattrError = unix.ENOTSUP
		},
	}
	for name, mutate := range cases {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if mutate == nil {
				manifest, err := validateFixedBinaryIdentityFilesystemV1WithOps(nil)
				if !errors.Is(err, errBinaryIdentityManifestUnavailableV1) ||
					manifest != (binaryIdentityManifestV1{}) {
					t.Fatalf("nil operations escaped: manifest=%#v err=%v", manifest, err)
				}
				return
			}
			fixture := newBinaryIdentityFakeFilesystemV1(t)
			mutate(fixture)
			requireBinaryIdentityFilesystemRejectedForTest(t, fixture)
		})
	}
}

func TestFixedBinaryIdentityFilesystemV1RejectsMetadataDigestAndReplacementRaces(t *testing.T) {
	t.Parallel()

	type raceMutation struct {
		readName string
		mutate   func(*binaryIdentityFakeFilesystemV1, *binaryIdentityFakeNodeV1)
	}
	cases := map[string]raceMutation{
		"manifest content": {
			readName: binaryIdentityManifestFileNameV1,
			mutate: func(_ *binaryIdentityFakeFilesystemV1, node *binaryIdentityFakeNodeV1) {
				node.data[len(node.data)-2] ^= 1
			},
		},
		"manifest metadata": {
			readName: binaryIdentityManifestFileNameV1,
			mutate: func(_ *binaryIdentityFakeFilesystemV1, node *binaryIdentityFakeNodeV1) {
				node.facts.Mtime.Nsec++
			},
		},
		"peer content": {
			readName: binaryIdentityPeerFileNameV1,
			mutate: func(_ *binaryIdentityFakeFilesystemV1, node *binaryIdentityFakeNodeV1) {
				node.data[len(node.data)-1] ^= 1
			},
		},
		"broker ACL": {
			readName: binaryIdentityBrokerFileNameV1,
			mutate: func(_ *binaryIdentityFakeFilesystemV1, node *binaryIdentityFakeNodeV1) {
				node.accessACL = binaryIdentityXattrV1{present: true, encoded: []byte{1}}
			},
		},
		"bootstrap capability": {
			readName: binaryIdentityBootstrapFileNameV1,
			mutate: func(_ *binaryIdentityFakeFilesystemV1, node *binaryIdentityFakeNodeV1) {
				node.capabilities = binaryIdentityXattrV1{present: true, encoded: []byte{1}}
			},
		},
		"peer replacement": {
			readName: binaryIdentityPeerFileNameV1,
			mutate: func(fixture *binaryIdentityFakeFilesystemV1, node *binaryIdentityFakeNodeV1) {
				replacement := cloneBinaryIdentityNodeForTest(node)
				replacement.facts.Ino++
				replacement.facts.Ctime.Nsec++
				binaryIdentityNodeForTest(fixture, "usr", "libexec").children[node.name] = replacement
			},
		},
		"manifest replacement": {
			readName: binaryIdentityManifestFileNameV1,
			mutate: func(fixture *binaryIdentityFakeFilesystemV1, node *binaryIdentityFakeNodeV1) {
				replacement := cloneBinaryIdentityNodeForTest(node)
				replacement.facts.Ino++
				replacement.facts.Ctime.Nsec++
				binaryIdentityNodeForTest(fixture, "usr", "lib", "kyclash").children[node.name] = replacement
			},
		},
		"executable directory drift": {
			readName: binaryIdentityPeerFileNameV1,
			mutate: func(fixture *binaryIdentityFakeFilesystemV1, _ *binaryIdentityFakeNodeV1) {
				binaryIdentityNodeForTest(fixture, "usr", "libexec").facts.Ctime.Nsec++
			},
		},
		"ancestor drift": {
			readName: binaryIdentityBootstrapFileNameV1,
			mutate: func(fixture *binaryIdentityFakeFilesystemV1, _ *binaryIdentityFakeNodeV1) {
				binaryIdentityNodeForTest(fixture, "usr").facts.Mtime.Nsec++
			},
		},
		"executable directory replacement": {
			readName: binaryIdentityPeerFileNameV1,
			mutate: func(fixture *binaryIdentityFakeFilesystemV1, _ *binaryIdentityFakeNodeV1) {
				usr := binaryIdentityNodeForTest(fixture, "usr")
				replacement := cloneBinaryIdentityNodeForTest(usr.children["libexec"])
				replacement.facts.Ino++
				replacement.facts.Ctime.Nsec++
				usr.children["libexec"] = replacement
			},
		},
		"manifest directory replacement": {
			readName: binaryIdentityManifestFileNameV1,
			mutate: func(fixture *binaryIdentityFakeFilesystemV1, _ *binaryIdentityFakeNodeV1) {
				lib := binaryIdentityNodeForTest(fixture, "usr", "lib")
				replacement := cloneBinaryIdentityNodeForTest(lib.children["kyclash"])
				replacement.facts.Ino++
				replacement.facts.Ctime.Nsec++
				lib.children["kyclash"] = replacement
			},
		},
	}
	for name, race := range cases {
		name, race := name, race
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newBinaryIdentityFakeFilesystemV1(t)
			fixture.afterFirstReadFor = race.readName
			fixture.afterFirstRead = race.mutate
			requireBinaryIdentityFilesystemRejectedForTest(t, fixture)
			if !fixture.readHookUsed {
				t.Fatal("race injection did not execute")
			}
		})
	}
}

func TestFixedBinaryIdentityFilesystemV1RejectsNoncanonicalManifestAtFilesystemBoundary(t *testing.T) {
	t.Parallel()

	fixture := newBinaryIdentityFakeFilesystemV1(t)
	node := binaryIdentityNodeForTest(
		fixture,
		"usr",
		"lib",
		"kyclash",
		binaryIdentityManifestFileNameV1,
	)
	node.data = append(bytes.Clone(node.data), '\n')
	node.facts.Size = uint64(len(node.data))
	requireBinaryIdentityFilesystemRejectedForTest(t, fixture)
}

func TestReadBinaryIdentityFileV1RejectsInvalidBoundaries(t *testing.T) {
	t.Parallel()

	fixture := newBinaryIdentityFakeFilesystemV1(t)
	node := binaryIdentityNodeForTest(
		fixture,
		"usr",
		"libexec",
		binaryIdentityPeerFileNameV1,
	)
	descriptor := fixture.allocateDescriptor(node)
	defer fixture.close(descriptor)

	cases := []struct {
		name    string
		size    uint64
		maximum uint64
	}{
		{name: "zero size", size: 0, maximum: 1},
		{name: "zero maximum", size: 1, maximum: 0},
		{name: "over maximum", size: 2, maximum: 1},
	}
	for _, test := range cases {
		_, _, err := readBinaryIdentityFileV1(
			fixture,
			descriptor,
			test.size,
			test.maximum,
			false,
		)
		if !errors.Is(err, errBinaryIdentityManifestUnavailableV1) {
			t.Fatalf("%s boundary escaped: %v", test.name, err)
		}
	}
}

func TestValidBinaryIdentityPathComponentV1RejectsCallerPaths(t *testing.T) {
	t.Parallel()

	for _, component := range []string{"", ".", "..", "/usr", "usr/lib", "usr\x00lib"} {
		if validBinaryIdentityPathComponentV1(component) {
			t.Fatalf("caller path was accepted: %q", component)
		}
	}
	for _, component := range []string{"usr", "lib", "libexec", binaryIdentityPeerFileNameV1} {
		if !validBinaryIdentityPathComponentV1(component) {
			t.Fatalf("fixed component was rejected: %q", component)
		}
	}
}

func (fixture *binaryIdentityFakeFilesystemV1) String() string {
	return fmt.Sprintf(
		"binaryIdentityFakeFilesystemV1{open=%d openat2=%d close=%d live=%d}",
		len(fixture.openCalls),
		len(fixture.openatCalls),
		fixture.closeCalls,
		len(fixture.descriptors),
	)
}
