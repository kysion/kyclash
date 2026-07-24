package vmexternalpeerlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"syscall"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"golang.org/x/sys/unix"
)

const courierPollInterval = 50 * time.Millisecond

var ErrCourierStore = errors.New("external-peer courier store failed")

type ClientCourierInput struct {
	RunTicket      []byte
	ClientEnvelope []byte
	PeerEnvelope   []byte
	PeerArtifacts  externalpeer.PeerPublicArtifacts
}

func (input *ClientCourierInput) Clear() {
	if input == nil {
		return
	}
	clear(input.RunTicket)
	clear(input.ClientEnvelope)
	clear(input.PeerEnvelope)
	clear(input.PeerArtifacts.Descriptor)
	clear(input.PeerArtifacts.CADER)
	clear(input.PeerArtifacts.ServerCertificateDER)
	clear(input.PeerArtifacts.ClientCertificateDER)
	clear(input.PeerArtifacts.OverlayServerPublicKey)
	clear(input.PeerArtifacts.SystemSSHHostPublicKey)
	clear(input.PeerArtifacts.TransferManifest)
	*input = ClientCourierInput{}
}

type ClientCourierStore struct {
	outbox      *os.File
	inbox       *os.File
	outboxUID   uint32
	inboxUID    uint32
	requireRoot bool
	published   []string
}

func OpenClientCourierStore(consoleUID uint32) (*ClientCourierStore, error) {
	if consoleUID == 0 {
		return nil, ErrCourierStore
	}
	return openClientCourierStore(ClientOutboxRoot, ClientInboxRoot, 0, consoleUID, true)
}

func openClientCourierStore(outboxPath, inboxPath string, outboxUID, inboxUID uint32, requireRoot bool) (*ClientCourierStore, error) {
	if outboxPath == "" || inboxPath == "" || outboxPath == inboxPath || requireRoot && outboxUID != 0 {
		return nil, ErrCourierStore
	}
	outbox, err := openCourierDirectory(outboxPath, outboxUID, 0o711)
	if err != nil {
		return nil, err
	}
	inbox, err := openCourierDirectory(inboxPath, inboxUID, 0o700)
	if err != nil {
		_ = outbox.Close()
		return nil, err
	}
	return &ClientCourierStore{
		outbox: outbox, inbox: inbox, outboxUID: outboxUID, inboxUID: inboxUID, requireRoot: requireRoot,
	}, nil
}

func openCourierDirectory(path string, expectedUID uint32, expectedMode os.FileMode) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != expectedMode {
		return nil, ErrCourierStore
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID {
		return nil, ErrCourierStore
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrCourierStore
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrCourierStore
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, ErrCourierStore
	}
	return file, nil
}

func (store *ClientCourierStore) PublishClientBundle(runID string, artifacts externalpeer.ClientPublicArtifacts) ([]externalpeer.CourierFile, []byte, error) {
	if store == nil || store.outbox == nil || len(store.published) != 0 {
		return nil, nil, ErrCourierStore
	}
	payloads := [][]byte{artifacts.Descriptor, artifacts.TLSClientCSRDER, artifacts.OverlayClientPublicKey}
	files := make([]externalpeer.CourierFile, 0, len(payloads))
	for index, payload := range payloads {
		file, err := externalpeer.NewCourierFile(externalpeer.ClientArtifactNames[index], payload)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, file)
	}
	manifest, err := externalpeer.EncodeTransferManifest(runID, externalpeer.CourierClientToPeer, files)
	if err != nil {
		return nil, nil, err
	}
	for index, payload := range payloads {
		if err := store.publish(externalpeer.ClientArtifactNames[index], payload, 0o444); err != nil {
			clear(manifest)
			return nil, nil, err
		}
	}
	if err := store.publish(ClientManifestName, manifest, 0o444); err != nil {
		clear(manifest)
		return nil, nil, err
	}
	if err := store.publish(ClientReadyName, nil, 0o444); err != nil {
		clear(manifest)
		return nil, nil, err
	}
	if err := unix.Fsync(int(store.outbox.Fd())); err != nil {
		clear(manifest)
		return nil, nil, ErrCourierStore
	}
	return files, manifest, nil
}

func (store *ClientCourierStore) publish(name string, data []byte, mode uint32) error {
	if store == nil || store.outbox == nil || !validCourierName(name) || len(data) > externalpeer.MaxArtifactSize {
		return ErrCourierStore
	}
	descriptor, err := unix.Openat(
		int(store.outbox.Fd()), name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW,
		mode,
	)
	if err != nil {
		return ErrCourierStore
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = unix.Close(descriptor)
		return ErrCourierStore
	}
	succeeded := false
	defer func() {
		_ = file.Close()
		if !succeeded {
			_ = unix.Unlinkat(int(store.outbox.Fd()), name, 0)
		}
	}()
	if err := file.Chmod(os.FileMode(mode)); err != nil {
		return ErrCourierStore
	}
	if len(data) > 0 {
		written, err := file.Write(data)
		if err != nil || written != len(data) {
			return ErrCourierStore
		}
	}
	if err := file.Sync(); err != nil {
		return ErrCourierStore
	}
	info, err := file.Stat()
	stat, ok := infoSyscall(info)
	if err != nil || !ok || stat.Uid != store.outboxUID || stat.Nlink != 1 ||
		info.Mode().Perm() != os.FileMode(mode) || !info.Mode().IsRegular() || info.Size() != int64(len(data)) {
		return ErrCourierStore
	}
	succeeded = true
	store.published = append(store.published, name)
	return nil
}

func (store *ClientCourierStore) WaitPeerBundle(ctx context.Context) (ClientCourierInput, error) {
	if store == nil || store.inbox == nil {
		return ClientCourierInput{}, ErrCourierStore
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ticker := time.NewTicker(courierPollInterval)
	defer ticker.Stop()
	for {
		if err := unix.Fstatat(int(store.inbox.Fd()), PeerReadyName, &unix.Stat_t{}, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			return store.readPeerBundle()
		} else if !errors.Is(err, unix.ENOENT) {
			return ClientCourierInput{}, ErrCourierStore
		}
		select {
		case <-ctx.Done():
			return ClientCourierInput{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (store *ClientCourierStore) readPeerBundle() (ClientCourierInput, error) {
	expected := []string{
		RunTicketName,
		ClientEnvelopeName,
		externalpeer.PeerArtifactNames[0],
		externalpeer.PeerArtifactNames[1],
		externalpeer.PeerArtifactNames[2],
		externalpeer.PeerArtifactNames[3],
		externalpeer.PeerArtifactNames[4],
		externalpeer.PeerArtifactNames[5],
		externalpeer.PeerArtifactNames[6],
		PeerEnvelopeName,
		PeerReadyName,
	}
	if err := requireExactDirectoryEntries(store.inbox, expected); err != nil {
		return ClientCourierInput{}, err
	}
	read := func(name string) ([]byte, error) {
		return readStableCourierFile(store.inbox, name, store.inboxUID)
	}
	var result ClientCourierInput
	var err error
	defer func() {
		if err != nil {
			result.Clear()
		}
	}()
	if result.RunTicket, err = read(RunTicketName); err != nil {
		return ClientCourierInput{}, err
	}
	if result.ClientEnvelope, err = read(ClientEnvelopeName); err != nil {
		return ClientCourierInput{}, err
	}
	peerPayloads := []*[]byte{
		&result.PeerArtifacts.Descriptor,
		&result.PeerArtifacts.CADER,
		&result.PeerArtifacts.ServerCertificateDER,
		&result.PeerArtifacts.ClientCertificateDER,
		&result.PeerArtifacts.OverlayServerPublicKey,
		&result.PeerArtifacts.SystemSSHHostPublicKey,
		&result.PeerArtifacts.TransferManifest,
	}
	for index, destination := range peerPayloads {
		if *destination, err = read(externalpeer.PeerArtifactNames[index]); err != nil {
			return ClientCourierInput{}, err
		}
	}
	if result.PeerEnvelope, err = read(PeerEnvelopeName); err != nil {
		return ClientCourierInput{}, err
	}
	ready, err := read(PeerReadyName)
	if err != nil || len(ready) != 0 {
		clear(ready)
		return ClientCourierInput{}, ErrCourierStore
	}
	return result, nil
}

func readStableCourierFile(directory *os.File, name string, expectedUID uint32) ([]byte, error) {
	if directory == nil || !validCourierName(name) {
		return nil, ErrCourierStore
	}
	descriptor, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrCourierStore
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrCourierStore
	}
	defer file.Close()
	before, err := file.Stat()
	beforeStat, ok := infoSyscall(before)
	if err != nil || !ok || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 ||
		beforeStat.Uid != expectedUID || beforeStat.Nlink != 1 || before.Size() < 0 || before.Size() > externalpeer.MaxArtifactSize {
		return nil, ErrCourierStore
	}
	data, err := io.ReadAll(io.LimitReader(file, externalpeer.MaxArtifactSize+1))
	if err != nil || len(data) > externalpeer.MaxArtifactSize || int64(len(data)) != before.Size() {
		clear(data)
		return nil, ErrCourierStore
	}
	after, err := file.Stat()
	afterStat, afterOK := infoSyscall(after)
	if err != nil || !afterOK || !stableCourierIdentity(before, beforeStat, after, afterStat) {
		clear(data)
		return nil, ErrCourierStore
	}
	return data, nil
}

func stableCourierIdentity(before os.FileInfo, beforeStat *syscall.Stat_t, after os.FileInfo, afterStat *syscall.Stat_t) bool {
	return beforeStat.Dev == afterStat.Dev && beforeStat.Ino == afterStat.Ino &&
		beforeStat.Uid == afterStat.Uid && beforeStat.Nlink == afterStat.Nlink &&
		before.Mode() == after.Mode() && before.Size() == after.Size() &&
		before.ModTime().UnixNano() == after.ModTime().UnixNano()
}

func infoSyscall(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	return value, ok
}

func requireExactDirectoryEntries(directory *os.File, expected []string) error {
	if directory == nil {
		return ErrCourierStore
	}
	descriptor, err := unix.Dup(int(directory.Fd()))
	if err != nil {
		return ErrCourierStore
	}
	clone := os.NewFile(uintptr(descriptor), directory.Name())
	if clone == nil {
		_ = unix.Close(descriptor)
		return ErrCourierStore
	}
	defer clone.Close()
	entries, err := clone.ReadDir(-1)
	if err != nil {
		return ErrCourierStore
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		actual = append(actual, entry.Name())
	}
	sort.Strings(actual)
	want := append([]string(nil), expected...)
	sort.Strings(want)
	if len(actual) != len(want) {
		return fmt.Errorf("%w: unexpected inbox entry count", ErrCourierStore)
	}
	for index := range want {
		if actual[index] != want[index] || !validCourierName(actual[index]) {
			return ErrCourierStore
		}
	}
	return nil
}

func validCourierName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func (store *ClientCourierStore) Close() error {
	if store == nil {
		return nil
	}
	var result error
	if store.inbox != nil {
		result = errors.Join(result, store.inbox.Close())
		store.inbox = nil
	}
	if store.outbox != nil {
		result = errors.Join(result, store.outbox.Close())
		store.outbox = nil
	}
	return result
}

// Cleanup removes only the fixed public-artifact names through the retained
// directory descriptors, fsyncs both directories, and positively proves they
// are empty. An unknown entry is never broadened into a recursive deletion;
// it remains a fail-closed residue for the next supervisor recovery check.
func (store *ClientCourierStore) Cleanup() error {
	if store == nil || store.outbox == nil || store.inbox == nil {
		return ErrCourierStore
	}
	var result error
	for _, name := range store.published {
		if err := unlinkCourierEntry(store.outbox, name); err != nil {
			result = errors.Join(result, err)
		}
	}
	inboxNames := []string{RunTicketName, ClientEnvelopeName, PeerEnvelopeName, PeerReadyName}
	inboxNames = append(inboxNames, externalpeer.PeerArtifactNames[:]...)
	for _, name := range inboxNames {
		if err := unlinkCourierEntry(store.inbox, name); err != nil {
			result = errors.Join(result, err)
		}
	}
	if err := unix.Fsync(int(store.outbox.Fd())); err != nil {
		result = errors.Join(result, ErrCourierStore)
	}
	if err := unix.Fsync(int(store.inbox.Fd())); err != nil {
		result = errors.Join(result, ErrCourierStore)
	}
	if err := requireExactDirectoryEntries(store.outbox, nil); err != nil {
		result = errors.Join(result, err)
	}
	if err := requireExactDirectoryEntries(store.inbox, nil); err != nil {
		result = errors.Join(result, err)
	}
	if result == nil {
		store.published = nil
	}
	return result
}

func unlinkCourierEntry(directory *os.File, name string) error {
	if directory == nil || !validCourierName(name) {
		return ErrCourierStore
	}
	err := unix.Unlinkat(int(directory.Fd()), name, 0)
	if err == nil || errors.Is(err, unix.ENOENT) {
		return nil
	}
	return ErrCourierStore
}
