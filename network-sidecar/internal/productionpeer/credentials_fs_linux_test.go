//go:build linux

package productionpeer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const systemdCredentialPeerUIDForTest uint32 = 64210

type systemdCredentialFakeObjectV2 struct {
	name           string
	facts          unix.Statx_t
	mount          unix.Statfs_t
	accessPresent  bool
	accessACL      []byte
	defaultPresent bool
	defaultACL     []byte
	data           []byte
}

type systemdCredentialOpenatCallV2 struct {
	directoryDescriptor int
	path                string
	how                 unix.OpenHow
}

type systemdCredentialFakeFilesystemV2 struct {
	nextDescriptor int
	root           *systemdCredentialFakeObjectV2
	directory      *systemdCredentialFakeObjectV2
	named          map[string]*systemdCredentialFakeObjectV2
	descriptors    map[int]*systemdCredentialFakeObjectV2
	directoryPath  string

	openCalls   int
	openatCalls []systemdCredentialOpenatCallV2
	closeCalls  int

	directorySnapshots  [][]string
	directoryReadCount  int
	beforeDirectoryRead func(*systemdCredentialFakeFilesystemV2, int)

	rejectOpenName string
	afterFirstRead func(*systemdCredentialFakeFilesystemV2, *systemdCredentialFakeObjectV2)
	readHookUsed   bool
	readBuffers    [][]byte
}

func (fixture *systemdCredentialFakeFilesystemV2) allocateDescriptor(
	object *systemdCredentialFakeObjectV2,
) int {
	descriptor := fixture.nextDescriptor
	fixture.nextDescriptor++
	fixture.descriptors[descriptor] = object
	return descriptor
}

func (fixture *systemdCredentialFakeFilesystemV2) open(
	path string,
	flags int,
	_ uint32,
) (int, error) {
	fixture.openCalls++
	if path != "/" ||
		flags&unix.O_PATH == 0 ||
		flags&unix.O_DIRECTORY == 0 ||
		flags&unix.O_CLOEXEC == 0 ||
		flags&unix.O_NOFOLLOW == 0 ||
		flags&unix.O_NONBLOCK != 0 {
		return -1, unix.EINVAL
	}
	return fixture.allocateDescriptor(fixture.root), nil
}

func (fixture *systemdCredentialFakeFilesystemV2) openat2(
	directoryDescriptor int,
	path string,
	how *unix.OpenHow,
) (int, error) {
	if how == nil {
		return -1, unix.EINVAL
	}
	fixture.openatCalls = append(fixture.openatCalls, systemdCredentialOpenatCallV2{
		directoryDescriptor: directoryDescriptor,
		path:                path,
		how:                 *how,
	})
	parent := fixture.descriptors[directoryDescriptor]
	switch {
	case parent == fixture.root && path == fixture.directoryPath:
		return fixture.allocateDescriptor(fixture.directory), nil
	case parent == fixture.directory && validCredentialName(path):
		if path == fixture.rejectOpenName {
			return -1, unix.ELOOP
		}
		object := fixture.named[path]
		if object == nil {
			return -1, unix.ENOENT
		}
		return fixture.allocateDescriptor(object), nil
	default:
		return -1, unix.EPERM
	}
}

func (fixture *systemdCredentialFakeFilesystemV2) close(descriptor int) error {
	if fixture.descriptors[descriptor] == nil {
		return unix.EBADF
	}
	delete(fixture.descriptors, descriptor)
	fixture.closeCalls++
	return nil
}

func (fixture *systemdCredentialFakeFilesystemV2) statx(
	directoryDescriptor int,
	path string,
	_ int,
	_ int,
	facts *unix.Statx_t,
) error {
	if facts == nil {
		return unix.EFAULT
	}
	var object *systemdCredentialFakeObjectV2
	if path == "" {
		object = fixture.descriptors[directoryDescriptor]
	} else if fixture.descriptors[directoryDescriptor] == fixture.directory {
		object = fixture.named[path]
	}
	if object == nil {
		return unix.ENOENT
	}
	*facts = object.facts
	return nil
}

func (fixture *systemdCredentialFakeFilesystemV2) fstatfs(
	descriptor int,
	facts *unix.Statfs_t,
) error {
	object := fixture.descriptors[descriptor]
	if object == nil || facts == nil {
		return unix.EBADF
	}
	*facts = object.mount
	return nil
}

func (fixture *systemdCredentialFakeFilesystemV2) readDirectoryNames(
	ctx context.Context,
	descriptor int,
) ([]string, error) {
	if fixture.descriptors[descriptor] != fixture.directory ||
		credentialContextDoneV2(ctx) {
		return nil, ErrCredentialUnavailable
	}
	fixture.directoryReadCount++
	if fixture.beforeDirectoryRead != nil {
		fixture.beforeDirectoryRead(fixture, fixture.directoryReadCount)
	}
	var names []string
	index := fixture.directoryReadCount - 1
	if index < len(fixture.directorySnapshots) {
		names = append(names, fixture.directorySnapshots[index]...)
	} else {
		for name := range fixture.named {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (fixture *systemdCredentialFakeFilesystemV2) readXattr(
	descriptor int,
	name string,
) (systemdCredentialXattrV2, error) {
	object := fixture.descriptors[descriptor]
	if object == nil {
		return systemdCredentialXattrV2{}, unix.EBADF
	}
	switch name {
	case systemdCredentialAccessACLXattr:
		return systemdCredentialXattrV2{
			present: object.accessPresent,
			encoded: bytes.Clone(object.accessACL),
		}, nil
	case systemdCredentialDefaultACLXattr:
		return systemdCredentialXattrV2{
			present: object.defaultPresent,
			encoded: bytes.Clone(object.defaultACL),
		}, nil
	default:
		return systemdCredentialXattrV2{}, unix.ENODATA
	}
}

func (fixture *systemdCredentialFakeFilesystemV2) pread(
	descriptor int,
	destination []byte,
	offset int64,
) (int, error) {
	object := fixture.descriptors[descriptor]
	if object == nil || offset < 0 {
		return 0, unix.EBADF
	}
	if offset == 0 && len(destination) > 0 {
		fixture.readBuffers = append(
			fixture.readBuffers,
			destination[:cap(destination)],
		)
	}
	if offset >= int64(len(object.data)) {
		return 0, nil
	}
	count := copy(destination, object.data[offset:])
	if count > 0 && !fixture.readHookUsed && fixture.afterFirstRead != nil {
		fixture.readHookUsed = true
		fixture.afterFirstRead(fixture, object)
	}
	return count, nil
}

func newSystemdCredentialFakeFilesystemV2(
	profile systemdCredentialMaterializationProfileV2,
) *systemdCredentialFakeFilesystemV2 {
	mountFlags := int64(unix.ST_NODEV | unix.ST_NOSUID | unix.ST_NOEXEC)
	directoryUID := uint32(0)
	directoryGID := uint32(0)
	directoryMode := uint16(systemdCredentialDirectoryRootACLMode)
	fileUID := uint32(0)
	fileGID := uint32(0)
	fileMode := uint16(systemdCredentialFileRootACLMode)
	directoryAccess := encodeSystemdCredentialACLForTest(
		systemdCredentialACLVersion,
		validSystemdCredentialACLEntriesForTest(
			systemdCredentialPeerUIDForTest,
			systemdCredentialACLRead|systemdCredentialACLExecute,
		)...,
	)
	fileAccess := encodeSystemdCredentialACLForTest(
		systemdCredentialACLVersion,
		validSystemdCredentialACLEntriesForTest(
			systemdCredentialPeerUIDForTest,
			systemdCredentialACLRead,
		)...,
	)
	accessPresent := true
	if profile == systemdCredentialMaterializationPeerOwnedReadOnlyV2 {
		mountFlags |= unix.ST_RDONLY
		directoryUID = systemdCredentialPeerUIDForTest
		directoryGID = systemdCredentialPeerUIDForTest + 1
		directoryMode = uint16(systemdCredentialDirectoryOwnerMode)
		fileUID = systemdCredentialPeerUIDForTest
		fileGID = systemdCredentialPeerUIDForTest + 1
		fileMode = uint16(systemdCredentialFileOwnerMode)
		directoryAccess = nil
		fileAccess = nil
		accessPresent = false
	}

	mount := unix.Statfs_t{
		Type:  0x01021994,
		Flags: mountFlags,
		Fsid: unix.Fsid{
			Val: [2]int32{17, 19},
		},
	}
	fixture := &systemdCredentialFakeFilesystemV2{
		nextDescriptor: 100,
		root: &systemdCredentialFakeObjectV2{
			name: "root",
		},
		directoryPath: "run/credentials/net.kysion.kyclash.network-peer.service",
		descriptors:   make(map[int]*systemdCredentialFakeObjectV2),
		named:         make(map[string]*systemdCredentialFakeObjectV2),
	}
	fixture.directory = &systemdCredentialFakeObjectV2{
		name:          "credentials-directory",
		facts:         systemdCredentialRawFactsForTest(directoryMode, directoryUID, directoryGID, 4096, 2, 41),
		mount:         mount,
		accessPresent: accessPresent,
		accessACL:     directoryAccess,
	}
	contents := map[string][]byte{
		TLSCertificateCredentialName:   []byte("synthetic-certificate-chain"),
		TLSPrivateKeyCredentialName:    []byte("synthetic-tls-private-key"),
		WireGuardPrivateCredentialName: []byte("synthetic-wireguard-private-key"),
	}
	inode := uint64(50)
	for _, specification := range systemdCredentialSpecsV2 {
		content := contents[specification.name]
		fixture.named[specification.name] = &systemdCredentialFakeObjectV2{
			name:          specification.name,
			facts:         systemdCredentialRawFactsForTest(fileMode, fileUID, fileGID, uint64(len(content)), 1, inode),
			mount:         mount,
			accessPresent: accessPresent,
			accessACL:     bytes.Clone(fileAccess),
			data:          bytes.Clone(content),
		}
		inode++
	}
	return fixture
}

func systemdCredentialRawFactsForTest(
	mode uint16,
	uid uint32,
	gid uint32,
	size uint64,
	nlink uint32,
	inode uint64,
) unix.Statx_t {
	return unix.Statx_t{
		Mask:            uint32(systemdCredentialStatxMaskV2()),
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

func systemdCredentialDirectoryForTest(
	fixture *systemdCredentialFakeFilesystemV2,
) string {
	return "/" + fixture.directoryPath
}

func allZeroSystemdCredentialBuffersForTest(buffers [][]byte) bool {
	for _, buffer := range buffers {
		for _, value := range buffer {
			if value != 0 {
				return false
			}
		}
	}
	return true
}

func TestSystemdCredentialFilesystemV2AcceptsBothLockedProfilesAtomically(t *testing.T) {
	t.Parallel()

	for _, profile := range []systemdCredentialMaterializationProfileV2{
		systemdCredentialMaterializationRootACLV2,
		systemdCredentialMaterializationPeerOwnedReadOnlyV2,
	} {
		profile := profile
		t.Run(string(rune(profile)), func(t *testing.T) {
			t.Parallel()
			fixture := newSystemdCredentialFakeFilesystemV2(profile)
			loaded, err := readSystemdCredentialFilesystemV2WithOps(
				context.Background(),
				systemdCredentialDirectoryForTest(fixture),
				systemdCredentialPeerUIDForTest,
				fixture,
			)
			if err != nil {
				t.Fatal(err)
			}
			if loaded == nil ||
				!bytes.Equal(loaded.tlsCertificatePEM, fixture.named[TLSCertificateCredentialName].data) ||
				!bytes.Equal(loaded.tlsPrivateKeyPEM, fixture.named[TLSPrivateKeyCredentialName].data) ||
				!bytes.Equal(loaded.wireGuardPrivateKey, fixture.named[WireGuardPrivateCredentialName].data) {
				t.Fatal("atomic credential result did not contain the exact three fixed inputs")
			}
			for _, formatted := range []string{
				loaded.String(),
				fmt.Sprintf("%v", loaded),
				fmt.Sprintf("%+v", loaded),
				fmt.Sprintf("%#v", loaded),
				fmt.Sprintf("%s", loaded),
				fmt.Sprintf("%q", loaded),
				fmt.Sprintf("%v", *loaded),
				fmt.Sprintf("%+v", *loaded),
				fmt.Sprintf("%#v", *loaded),
			} {
				if strings.Contains(formatted, "synthetic-") ||
					!strings.Contains(formatted, "<redacted>") {
					t.Fatal("credential set formatting exposed synthetic secret bytes")
				}
			}
			if len(fixture.readBuffers) != len(systemdCredentialSpecsV2) {
				t.Fatalf("unexpected read allocation count: %d", len(fixture.readBuffers))
			}
			assertSystemdCredentialOpenatContractV2(t, fixture)
			if allZeroSystemdCredentialBuffersForTest(fixture.readBuffers) {
				t.Fatal("successful credential result was cleared before Close")
			}
			loaded.Close()
			if !allZeroSystemdCredentialBuffersForTest(fixture.readBuffers) {
				t.Fatal("Close did not clear every complete fixed-capacity allocation")
			}
		})
	}
}

func assertSystemdCredentialOpenatContractV2(
	t *testing.T,
	fixture *systemdCredentialFakeFilesystemV2,
) {
	t.Helper()
	if fixture.openCalls != 1 || len(fixture.openatCalls) != 3+2*len(systemdCredentialSpecsV2) {
		t.Fatalf("unexpected descriptor-open contract: open=%d openat2=%d", fixture.openCalls, len(fixture.openatCalls))
	}
	requiredResolve := uint64(
		unix.RESOLVE_BENEATH |
			unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS,
	)
	for index, call := range fixture.openatCalls {
		if call.how.Resolve != requiredResolve ||
			call.how.Flags&unix.O_CLOEXEC == 0 ||
			call.how.Flags&unix.O_NOFOLLOW == 0 {
			t.Fatalf("openat2 call %d omitted a locked flag: %#v", index, call.how)
		}
		pathPinningCall := index%2 == 0 || index == len(fixture.openatCalls)-1
		if pathPinningCall {
			if call.how.Flags&unix.O_PATH == 0 ||
				call.how.Flags&unix.O_NONBLOCK != 0 {
				t.Fatalf("openat2 call %d used an invalid O_PATH flag set", index)
			}
		} else if call.how.Flags&unix.O_PATH != 0 ||
			call.how.Flags&unix.O_NONBLOCK == 0 {
			t.Fatalf("openat2 call %d did not use nonblocking data access", index)
		}
		if !pathPinningCall &&
			(call.how.Flags&unix.O_PATH != 0 ||
				call.how.Flags&uint64(unix.O_ACCMODE) != uint64(unix.O_RDONLY)) {
			t.Fatalf("openat2 call %d was not an O_RDONLY data descriptor: %#v", index, call.how)
		}
		directoryCall := index < 2 || index == len(fixture.openatCalls)-1
		if directoryCall {
			if call.path != fixture.directoryPath ||
				call.how.Flags&unix.O_DIRECTORY == 0 {
				t.Fatalf("directory openat2 contract drifted: %#v", call)
			}
		} else {
			if call.how.Flags&unix.O_DIRECTORY != 0 {
				t.Fatalf("credential file openat2 call %d unexpectedly requested O_DIRECTORY", index)
			}
			if !validCredentialName(call.path) || strings.Contains(call.path, "/") {
				t.Fatalf("non-fixed credential basename was opened: %q", call.path)
			}
		}
	}
	if fixture.closeCalls != fixture.openCalls+len(fixture.openatCalls) {
		t.Fatalf(
			"descriptor leak: opened=%d closed=%d",
			fixture.openCalls+len(fixture.openatCalls),
			fixture.closeCalls,
		)
	}
}

func TestSystemdCredentialFilesystemV2FailureClearsEarlierFiles(t *testing.T) {
	t.Parallel()

	fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
	fixture.named[TLSPrivateKeyCredentialName].facts.Mode = uint16(unix.S_IFREG | 0o600)
	loaded, err := readSystemdCredentialFilesystemV2WithOps(
		context.Background(),
		systemdCredentialDirectoryForTest(fixture),
		systemdCredentialPeerUIDForTest,
		fixture,
	)
	if loaded != nil || !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("partial credential result escaped: loaded=%v err=%v", loaded, err)
	}
	if len(fixture.readBuffers) != 1 ||
		!allZeroSystemdCredentialBuffersForTest(fixture.readBuffers) {
		t.Fatal("a later-file failure did not clear the complete earlier allocation")
	}
}

func TestSystemdCredentialFilesystemV2CancellationIsAllOrNothing(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
	fixture.afterFirstRead = func(
		_ *systemdCredentialFakeFilesystemV2,
		_ *systemdCredentialFakeObjectV2,
	) {
		cancel()
	}
	loaded, err := readSystemdCredentialFilesystemV2WithOps(
		ctx,
		systemdCredentialDirectoryForTest(fixture),
		systemdCredentialPeerUIDForTest,
		fixture,
	)
	if loaded != nil || !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("cancelled read escaped a result: loaded=%v err=%v", loaded, err)
	}
	if len(fixture.readBuffers) != 1 ||
		!allZeroSystemdCredentialBuffersForTest(fixture.readBuffers) {
		t.Fatal("cancelled read did not clear its full fixed allocation")
	}

	preCancelled, stop := context.WithCancel(context.Background())
	stop()
	unopened := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
	if loaded, err := readSystemdCredentialFilesystemV2WithOps(
		preCancelled,
		systemdCredentialDirectoryForTest(unopened),
		systemdCredentialPeerUIDForTest,
		unopened,
	); loaded != nil || !errors.Is(err, ErrCredentialUnavailable) || unopened.openCalls != 0 {
		t.Fatalf("pre-cancelled operation touched the filesystem: loaded=%v err=%v opens=%d", loaded, err, unopened.openCalls)
	}
}

func TestSystemdCredentialFilesystemV2RejectsEntryAndObjectRaces(t *testing.T) {
	t.Parallel()

	t.Run("extra entry before reads", func(t *testing.T) {
		t.Parallel()
		fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
		fixture.directorySnapshots = [][]string{{
			TLSCertificateCredentialName,
			TLSPrivateKeyCredentialName,
			WireGuardPrivateCredentialName,
			"unexpected",
		}}
		assertSystemdCredentialFilesystemV2RefusedAndCleared(t, fixture)
	})

	t.Run("missing entry before reads", func(t *testing.T) {
		t.Parallel()
		fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
		fixture.directorySnapshots = [][]string{{
			TLSCertificateCredentialName,
			TLSPrivateKeyCredentialName,
		}}
		assertSystemdCredentialFilesystemV2RefusedAndCleared(t, fixture)
	})

	t.Run("entry set changes after reads", func(t *testing.T) {
		t.Parallel()
		fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
		fixture.directorySnapshots = [][]string{
			{
				TLSCertificateCredentialName,
				TLSPrivateKeyCredentialName,
				WireGuardPrivateCredentialName,
			},
			{
				TLSCertificateCredentialName,
				TLSPrivateKeyCredentialName,
				"unexpected",
			},
		}
		assertSystemdCredentialFilesystemV2RefusedAndCleared(t, fixture)
	})

	mutations := map[string]func(*systemdCredentialFakeFilesystemV2, *systemdCredentialFakeObjectV2){
		"mode": func(_ *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			object.facts.Mode ^= 0o020
		},
		"uid": func(_ *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			object.facts.Uid++
		},
		"gid": func(_ *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			object.facts.Gid++
		},
		"nlink": func(_ *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			object.facts.Nlink++
		},
		"size": func(_ *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			object.facts.Size++
		},
		"ctime": func(_ *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			object.facts.Ctime.Nsec++
		},
		"mtime": func(_ *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			object.facts.Mtime.Nsec++
		},
		"attributes": func(_ *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			object.facts.Attributes ^= 1
		},
		"mount flags": func(_ *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			object.mount.Flags ^= unix.ST_NOEXEC
		},
		"mount filesystem": func(_ *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			object.mount.Type++
		},
		"mount id": func(_ *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			object.facts.Mnt_id++
		},
		"access ACL": func(_ *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			object.accessACL[len(object.accessACL)-1] ^= 1
		},
		"name replacement": func(fixture *systemdCredentialFakeFilesystemV2, object *systemdCredentialFakeObjectV2) {
			replacement := *object
			replacement.facts.Ino += 1000
			replacement.data = bytes.Clone(object.data)
			replacement.accessACL = bytes.Clone(object.accessACL)
			fixture.named[object.name] = &replacement
		},
	}
	for name, mutate := range mutations {
		name := name
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
			fixture.afterFirstRead = mutate
			assertSystemdCredentialFilesystemV2RefusedAndCleared(t, fixture)
		})
	}

	t.Run("directory metadata drift", func(t *testing.T) {
		t.Parallel()
		fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
		fixture.beforeDirectoryRead = func(
			fixture *systemdCredentialFakeFilesystemV2,
			readNumber int,
		) {
			if readNumber == 2 {
				fixture.directory.facts.Ctime.Nsec++
			}
		}
		assertSystemdCredentialFilesystemV2RefusedAndCleared(t, fixture)
	})

	t.Run("directory access ACL drift", func(t *testing.T) {
		t.Parallel()
		fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
		fixture.beforeDirectoryRead = func(
			fixture *systemdCredentialFakeFilesystemV2,
			readNumber int,
		) {
			if readNumber == 2 {
				fixture.directory.accessACL[len(fixture.directory.accessACL)-1] ^= 1
			}
		}
		assertSystemdCredentialFilesystemV2RefusedAndCleared(t, fixture)
	})

	t.Run("absolute directory path replacement", func(t *testing.T) {
		t.Parallel()
		fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
		fixture.beforeDirectoryRead = func(
			fixture *systemdCredentialFakeFilesystemV2,
			readNumber int,
		) {
			if readNumber != 2 {
				return
			}
			replacement := *fixture.directory
			replacement.facts.Ino += 2000
			replacement.accessACL = bytes.Clone(fixture.directory.accessACL)
			fixture.directory = &replacement
		}
		assertSystemdCredentialFilesystemV2RefusedAndCleared(t, fixture)
	})
}

func TestSystemdCredentialFilesystemV2IgnoresAtimeOnly(t *testing.T) {
	t.Parallel()

	fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
	fixture.afterFirstRead = func(
		_ *systemdCredentialFakeFilesystemV2,
		object *systemdCredentialFakeObjectV2,
	) {
		object.facts.Atime.Sec++
		object.facts.Atime.Nsec++
	}
	loaded, err := readSystemdCredentialFilesystemV2WithOps(
		context.Background(),
		systemdCredentialDirectoryForTest(fixture),
		systemdCredentialPeerUIDForTest,
		fixture,
	)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Close()
}

func TestSystemdCredentialFilesystemV2RejectsUnsafeContentAndLinks(t *testing.T) {
	t.Parallel()

	t.Run("device is rejected before data open", func(t *testing.T) {
		t.Parallel()
		fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
		fixture.named[TLSCertificateCredentialName].facts.Mode = uint16(unix.S_IFCHR | 0o440)
		assertSystemdCredentialFilesystemV2RefusedAndCleared(t, fixture)
		if len(fixture.openatCalls) != 3 {
			t.Fatalf("unsafe device reached a data open: openat2 calls=%d", len(fixture.openatCalls))
		}
	})

	tests := map[string]func(*systemdCredentialFakeFilesystemV2){
		"empty": func(fixture *systemdCredentialFakeFilesystemV2) {
			object := fixture.named[WireGuardPrivateCredentialName]
			object.data = nil
			object.facts.Size = 0
		},
		"NUL": func(fixture *systemdCredentialFakeFilesystemV2) {
			object := fixture.named[WireGuardPrivateCredentialName]
			object.data = []byte{'a', 0, 'b'}
			object.facts.Size = uint64(len(object.data))
		},
		"hard link": func(fixture *systemdCredentialFakeFilesystemV2) {
			fixture.named[WireGuardPrivateCredentialName].facts.Nlink = 2
		},
		"symlink": func(fixture *systemdCredentialFakeFilesystemV2) {
			fixture.rejectOpenName = WireGuardPrivateCredentialName
		},
	}
	for name, prepare := range tests {
		name := name
		prepare := prepare
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
			prepare(fixture)
			assertSystemdCredentialFilesystemV2RefusedAndCleared(t, fixture)
		})
	}
	initialFacts := map[string]func(*systemdCredentialFakeFilesystemV2){
		"wrong root file uid": func(fixture *systemdCredentialFakeFilesystemV2) {
			fixture.named[TLSCertificateCredentialName].facts.Uid = 1
		},
		"wrong root file gid": func(fixture *systemdCredentialFakeFilesystemV2) {
			fixture.named[TLSCertificateCredentialName].facts.Gid = 1
		},
		"default file ACL": func(fixture *systemdCredentialFakeFilesystemV2) {
			object := fixture.named[TLSCertificateCredentialName]
			object.defaultPresent = true
			object.defaultACL = []byte{1}
		},
	}
	for name, prepare := range initialFacts {
		name := name
		prepare := prepare
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
			prepare(fixture)
			assertSystemdCredentialFilesystemV2RefusedAndCleared(t, fixture)
		})
	}
	for _, specification := range systemdCredentialSpecsV2 {
		specification := specification
		t.Run("oversize "+specification.name, func(t *testing.T) {
			t.Parallel()
			fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
			object := fixture.named[specification.name]
			object.data = bytes.Repeat([]byte{'x'}, specification.maximum+1)
			object.facts.Size = uint64(len(object.data))
			assertSystemdCredentialFilesystemV2RefusedAndCleared(t, fixture)
		})
	}
}

func TestSystemdCredentialFilesystemV2AcceptsEachExactMaximum(t *testing.T) {
	t.Parallel()

	for _, specification := range systemdCredentialSpecsV2 {
		specification := specification
		t.Run(specification.name, func(t *testing.T) {
			t.Parallel()
			fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
			object := fixture.named[specification.name]
			object.data = bytes.Repeat([]byte{'x'}, specification.maximum)
			object.facts.Size = uint64(len(object.data))
			loaded, err := readSystemdCredentialFilesystemV2WithOps(
				context.Background(),
				systemdCredentialDirectoryForTest(fixture),
				systemdCredentialPeerUIDForTest,
				fixture,
			)
			if err != nil {
				t.Fatal(err)
			}
			loaded.Close()
		})
	}
}

func assertSystemdCredentialFilesystemV2RefusedAndCleared(
	t *testing.T,
	fixture *systemdCredentialFakeFilesystemV2,
) {
	t.Helper()
	loaded, err := readSystemdCredentialFilesystemV2WithOps(
		context.Background(),
		systemdCredentialDirectoryForTest(fixture),
		systemdCredentialPeerUIDForTest,
		fixture,
	)
	if loaded != nil || !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("unsafe filesystem returned credentials: loaded=%v err=%v", loaded, err)
	}
	if !allZeroSystemdCredentialBuffersForTest(fixture.readBuffers) {
		t.Fatal("failed filesystem transaction retained credential bytes")
	}
}

func TestClassifySystemdCredentialObservationV2RejectsExpandedProfiles(t *testing.T) {
	t.Parallel()

	root := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
	rootDirectory, err := observeSystemdCredentialDescriptorForFakeTest(root, root.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer rootDirectory.clear()
	if classifySystemdCredentialObservationV2(
		rootDirectory,
		systemdCredentialPeerUIDForTest,
		true,
		0,
	) != systemdCredentialMaterializationRootACLV2 {
		t.Fatal("exact root ACL directory profile was rejected")
	}

	owner := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationPeerOwnedReadOnlyV2)
	ownerFile, err := observeSystemdCredentialDescriptorForFakeTest(
		owner,
		owner.named[TLSPrivateKeyCredentialName],
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerFile.clear()
	if classifySystemdCredentialObservationV2(
		ownerFile,
		systemdCredentialPeerUIDForTest,
		false,
		MaxTLSPrivateKeyCredentialSize,
	) != systemdCredentialMaterializationPeerOwnedReadOnlyV2 {
		t.Fatal("exact Peer-owned read-only profile was rejected")
	}

	invalidRoot := []struct {
		name   string
		mutate func(*systemdCredentialObservationV2)
	}{
		{name: "wrong gid", mutate: func(candidate *systemdCredentialObservationV2) { candidate.object.gid = 1 }},
		{name: "writable mode", mutate: func(candidate *systemdCredentialObservationV2) { candidate.object.mode |= 0o020 }},
		{name: "missing ACL", mutate: func(candidate *systemdCredentialObservationV2) { candidate.accessACL.present = false }},
		{name: "default ACL", mutate: func(candidate *systemdCredentialObservationV2) { candidate.defaultACL.present = true }},
		{name: "expanded ACL", mutate: func(candidate *systemdCredentialObservationV2) {
			candidate.accessACL.encoded = append(candidate.accessACL.encoded, make([]byte, systemdCredentialACLEntrySize)...)
		}},
	}
	for _, test := range invalidRoot {
		test := test
		t.Run("root "+test.name, func(t *testing.T) {
			candidate := cloneSystemdCredentialObservationForTest(rootDirectory)
			defer candidate.clear()
			test.mutate(&candidate)
			if classifySystemdCredentialObservationV2(
				candidate,
				systemdCredentialPeerUIDForTest,
				true,
				0,
			) != systemdCredentialMaterializationInvalidV2 {
				t.Fatal("expanded root ACL profile was accepted")
			}
		})
	}

	invalidOwner := []struct {
		name   string
		mutate func(*systemdCredentialObservationV2)
	}{
		{name: "writable mount", mutate: func(candidate *systemdCredentialObservationV2) { candidate.mount.flags &^= unix.ST_RDONLY }},
		{name: "access ACL", mutate: func(candidate *systemdCredentialObservationV2) { candidate.accessACL.present = true }},
		{name: "default ACL", mutate: func(candidate *systemdCredentialObservationV2) { candidate.defaultACL.present = true }},
		{name: "wrong uid", mutate: func(candidate *systemdCredentialObservationV2) { candidate.object.uid++ }},
		{name: "writable mode", mutate: func(candidate *systemdCredentialObservationV2) { candidate.object.mode |= 0o200 }},
		{name: "second link", mutate: func(candidate *systemdCredentialObservationV2) { candidate.object.nlink = 2 }},
	}
	for _, test := range invalidOwner {
		test := test
		t.Run("owner "+test.name, func(t *testing.T) {
			candidate := cloneSystemdCredentialObservationForTest(ownerFile)
			defer candidate.clear()
			test.mutate(&candidate)
			if classifySystemdCredentialObservationV2(
				candidate,
				systemdCredentialPeerUIDForTest,
				false,
				MaxTLSPrivateKeyCredentialSize,
			) != systemdCredentialMaterializationInvalidV2 {
				t.Fatal("expanded Peer-owned profile was accepted")
			}
		})
	}
}

func observeSystemdCredentialDescriptorForFakeTest(
	fixture *systemdCredentialFakeFilesystemV2,
	object *systemdCredentialFakeObjectV2,
) (systemdCredentialObservationV2, error) {
	descriptor := fixture.allocateDescriptor(object)
	defer fixture.close(descriptor)
	return observeSystemdCredentialDescriptorV2(fixture, descriptor)
}

func cloneSystemdCredentialObservationForTest(
	source systemdCredentialObservationV2,
) systemdCredentialObservationV2 {
	clone := source
	clone.accessACL.encoded = bytes.Clone(source.accessACL.encoded)
	clone.defaultACL.encoded = bytes.Clone(source.defaultACL.encoded)
	return clone
}

func TestCanonicalSystemdCredentialDirectoryV2(t *testing.T) {
	t.Parallel()

	valid := []string{
		"/run/credentials/net.kysion.kyclash.network-peer.service",
		"/run/credentials/123",
	}
	for _, path := range valid {
		if !canonicalSystemdCredentialDirectoryV2(path) {
			t.Fatalf("canonical path was rejected: %q", path)
		}
	}
	invalid := []string{
		"",
		"/",
		"run/credentials/unit",
		"/run/credentials/unit/",
		"//run/credentials/unit",
		"/run//credentials/unit",
		"/run/./credentials/unit",
		"/run/../credentials/unit",
		"/run/credentials/\x00unit",
	}
	for _, path := range invalid {
		if canonicalSystemdCredentialDirectoryV2(path) {
			t.Fatalf("non-canonical path was accepted: %q", path)
		}
		fixture := newSystemdCredentialFakeFilesystemV2(systemdCredentialMaterializationRootACLV2)
		if loaded, err := readSystemdCredentialFilesystemV2WithOps(
			context.Background(),
			path,
			systemdCredentialPeerUIDForTest,
			fixture,
		); loaded != nil || !errors.Is(err, ErrCredentialUnavailable) || fixture.openCalls != 0 {
			t.Fatalf("non-canonical path touched filesystem state: path=%q loaded=%v err=%v opens=%d", path, loaded, err, fixture.openCalls)
		}
	}
}

func TestSystemdCredentialFilesystemV2RejectsOrdinaryWritableTempFixture(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root-owned temp files cannot represent the nonzero Peer-owned writable negative")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, specification := range systemdCredentialSpecsV2 {
		if err := os.WriteFile(
			filepath.Join(directory, specification.name),
			[]byte("synthetic-only"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := readSystemdCredentialFilesystemV2(
		context.Background(),
		directory,
		uint32(os.Geteuid()),
	)
	if loaded != nil || !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("ordinary writable 0700/0600 fixture was accepted: loaded=%v err=%v", loaded, err)
	}
}
