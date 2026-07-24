package vmexternalpeerlab

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
)

func newCourierStoreFixture(t *testing.T) (*ClientCourierStore, string, string) {
	t.Helper()
	root := t.TempDir()
	outbox := filepath.Join(root, "outbox")
	inbox := filepath.Join(root, "inbox")
	if err := os.Mkdir(outbox, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outbox, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	store, err := openClientCourierStore(outbox, inbox, uid, uid, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, outbox, inbox
}

func TestClientCourierStorePublishesCreateOnlyPublicBundle(t *testing.T) {
	store, outbox, _ := newCourierStoreFixture(t)
	artifacts := externalpeer.ClientPublicArtifacts{
		Descriptor: []byte("descriptor"), TLSClientCSRDER: []byte("csr"),
		OverlayClientPublicKey: []byte("ssh-public"),
	}
	files, manifest, err := store.PublishClientBundle("run-12345678", artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(externalpeer.ClientArtifactNames) || len(manifest) == 0 {
		t.Fatalf("unexpected public bundle: %d %d", len(files), len(manifest))
	}
	for _, name := range append(append([]string(nil), externalpeer.ClientArtifactNames[:]...), ClientManifestName, ClientReadyName) {
		info, err := os.Lstat(filepath.Join(outbox, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
			t.Fatalf("unsafe public artifact %s: %#v %v", name, info, err)
		}
	}
	if _, _, err := store.PublishClientBundle("run-12345678", artifacts); err == nil {
		t.Fatal("published a second client bundle")
	}
	if err := store.Cleanup(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(outbox)
	if err != nil || len(entries) != 0 {
		t.Fatalf("client outbox was not cleaned: %v %v", entries, err)
	}
}

func writeCourierInboxFile(t *testing.T, directory, name string, data []byte) {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func populatePeerInbox(t *testing.T, inbox string) {
	t.Helper()
	writeCourierInboxFile(t, inbox, RunTicketName, []byte("ticket"))
	writeCourierInboxFile(t, inbox, ClientEnvelopeName, []byte("client-envelope"))
	for _, name := range externalpeer.PeerArtifactNames {
		writeCourierInboxFile(t, inbox, name, []byte("public:"+name))
	}
	writeCourierInboxFile(t, inbox, PeerEnvelopeName, []byte("peer-envelope"))
	writeCourierInboxFile(t, inbox, PeerReadyName, nil)
}

func TestClientCourierStoreConsumesOnlyExactStableInbox(t *testing.T) {
	store, _, inbox := newCourierStoreFixture(t)
	populatePeerInbox(t, inbox)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := store.WaitPeerBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Clear()
	if string(result.RunTicket) != "ticket" || string(result.ClientEnvelope) != "client-envelope" ||
		string(result.PeerEnvelope) != "peer-envelope" || len(result.PeerArtifacts.Descriptor) == 0 ||
		len(result.PeerArtifacts.TransferManifest) == 0 {
		t.Fatalf("unexpected peer input: %#v", result)
	}
	if err := store.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestClientCourierStoreRejectsExtraOrLooseInboxEntry(t *testing.T) {
	store, _, inbox := newCourierStoreFixture(t)
	populatePeerInbox(t, inbox)
	writeCourierInboxFile(t, inbox, "unexpected", []byte("x"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := store.WaitPeerBundle(ctx); err == nil {
		t.Fatal("accepted an extra inbox entry")
	}
}
