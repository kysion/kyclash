package externalpeer

import (
	"context"
	"encoding/base64"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type trackingWriteCloser struct {
	closed atomic.Bool
}

func (value *trackingWriteCloser) Write(data []byte) (int, error) {
	if value.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return len(data), nil
}

func (value *trackingWriteCloser) Close() error {
	value.closed.Store(true)
	return nil
}

func TestPeerChildResponseReaderIsSinglePersistentStream(t *testing.T) {
	reader, writer := io.Pipe()
	results := make(chan childReadResult, 1)
	go scanPeerChildResponses(reader, results)
	stdin := &trackingWriteCloser{}
	process := &PeerChildProcess{
		stdin:     stdin,
		responses: results,
	}
	go func() {
		_, _ = io.WriteString(
			writer,
			"{\"schema_version\":1,\"state\":\"running\"}\n"+
				"{\"schema_version\":1,\"state\":\"stopped\"}\n",
		)
		_ = writer.Close()
	}()
	first, err := process.readResponse(context.Background(), time.Second)
	if err != nil || first.State != "running" {
		t.Fatalf("unexpected first response: %#v %v", first, err)
	}
	second, err := process.readResponse(context.Background(), time.Second)
	if err != nil || second.State != "stopped" {
		t.Fatalf("unexpected second response: %#v %v", second, err)
	}
	if _, err := process.readResponse(context.Background(), time.Second); err == nil {
		t.Fatal("child response EOF was accepted")
	}
}

func TestPeerChildResponseTimeoutClosesAuthenticatedController(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	results := make(chan childReadResult, 1)
	go scanPeerChildResponses(reader, results)
	stdin := &trackingWriteCloser{}
	process := &PeerChildProcess{
		stdin:     stdin,
		responses: results,
	}
	if _, err := process.readResponse(
		context.Background(),
		10*time.Millisecond,
	); err == nil {
		t.Fatal("missing child response did not time out")
	}
	if !stdin.closed.Load() || !process.protocolFailed {
		t.Fatal("timed-out controller remained usable")
	}
}

func TestPeerChildExitsBeforeRuntimeWhenParentBootstrapPipeCloses(t *testing.T) {
	if err := RunPeerChild(
		context.Background(),
		&emptyReader{},
		io.Discard,
	); err != io.ErrUnexpectedEOF {
		t.Fatalf("bootstrap EOF was not fatal: %v", err)
	}
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

func TestChildBootstrapAndReadyResponseRoundTrip(t *testing.T) {
	fixture := newIdentityFixture(t)
	config := PeerConfig{
		RunID:     testRunID,
		Now:       fixture.now,
		ExpiresAt: fixture.now.Add(30 * time.Minute),
		Client: ClientExpectation{
			RunID:              testRunID,
			Now:                fixture.now,
			ClientPlatformUUID: testClientUUID,
			ClientIPv4:         testClientIP,
			ClientMAC:          testClientMAC,
			WireGuardPublicKey: append([]byte(nil), fixture.clientWGPublic...),
		},
		ClientArtifacts: ClientPublicArtifacts{
			Descriptor:             append([]byte(nil), fixture.clientArtifacts.Descriptor...),
			TLSClientCSRDER:        append([]byte(nil), fixture.clientArtifacts.TLSClientCSRDER...),
			OverlayClientPublicKey: append([]byte(nil), fixture.clientArtifacts.OverlayClientPublicKey...),
		},
		PeerPlatformUUID:       testPeerUUID,
		PeerIPv4:               netip.MustParseAddr(testPeerIP.String()),
		PeerMAC:                testPeerMAC,
		SystemSSHHostPublicKey: append([]byte(nil), fixture.systemHostPublic...),
	}
	defer clearPeerConfigPublicArtifacts(&config)
	encoded, err := encodeChildBootstrap(config)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := DecodeChildBootstrap(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer clearPeerConfigPublicArtifacts(&decoded)
	if decoded.RunID != config.RunID ||
		decoded.PeerIPv4 != config.PeerIPv4 {
		t.Fatalf("unexpected decoded bootstrap: %#v", decoded)
	}
	response := ChildResponse{
		SchemaVersion:                SchemaVersion,
		State:                        "ready",
		PeerDescriptorBase64:         base64.StdEncoding.EncodeToString(fixture.peerArtifacts.Descriptor),
		CADERBase64:                  base64.StdEncoding.EncodeToString(fixture.peerArtifacts.CADER),
		ServerCertificateDERBase64:   base64.StdEncoding.EncodeToString(fixture.peerArtifacts.ServerCertificateDER),
		ClientCertificateDERBase64:   base64.StdEncoding.EncodeToString(fixture.peerArtifacts.ClientCertificateDER),
		OverlayServerPublicKeyBase64: base64.StdEncoding.EncodeToString(fixture.peerArtifacts.OverlayServerPublicKey),
		SystemSSHHostPublicKeyBase64: base64.StdEncoding.EncodeToString(fixture.peerArtifacts.SystemSSHHostPublicKey),
		TransferManifestBase64:       base64.StdEncoding.EncodeToString(fixture.peerArtifacts.TransferManifest),
		RunNonceBase64:               base64.StdEncoding.EncodeToString(fixture.peerIdentity.RunNonce),
	}
	ready, err := decodePeerChildReady(
		response,
		config,
		fixture.clientDescriptor,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clearPeerChildReady(&ready)
	if ready.Descriptor.RunID != testRunID ||
		len(ready.RunNonce) != 32 {
		t.Fatalf("unexpected ready response: %#v", ready.Descriptor)
	}
}
