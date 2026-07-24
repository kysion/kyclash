package externalpeerhost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
)

func TestSequentialSignerRequiresClientBeforePeerAndNeverPresignsCancel(
	t *testing.T,
) {
	t.Parallel()
	fixture := newHostTransactionFixture(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	entropy := nonceEntropy(1, 2, 3, 4)
	signer, initial, err := NewTransactionSigner(
		fixture.input,
		privateKey,
		fixture.now,
		entropy,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	defer initial.Clear()
	if len(initial.RunTicket) == 0 || len(initial.ClientToPeer) == 0 {
		t.Fatal("initial sequence was not signed")
	}
	for _, envelope := range [][]byte{initial.RunTicket, initial.ClientToPeer} {
		message, err := externalpeer.VerifyCourierMessage(envelope, publicKey, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		if message.Kind != externalpeer.CourierRunTicket &&
			message.Kind != externalpeer.CourierClientToPeer {
			t.Fatalf("unexpected initial kind: %d", message.Kind)
		}
	}
	response, err := signer.SignPeerResponse(
		fixture.peer,
		fixture.now.Add(10*time.Second),
		entropy,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Clear()
	message, err := externalpeer.VerifyCourierMessage(
		response.PeerToClient,
		publicKey,
		fixture.now.Add(10*time.Second),
	)
	if err != nil || message.Kind != externalpeer.CourierPeerToClient {
		t.Fatalf("invalid peer response: kind=%d err=%v", message.Kind, err)
	}
	if _, err := signer.SignPeerResponse(
		fixture.peer,
		fixture.now.Add(11*time.Second),
		entropy,
	); err == nil {
		t.Fatal("sequence 2 replay was signed")
	}
	cancellation, err := signer.SignCancellation(
		fixture.now.Add(12*time.Second),
		entropy,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cancellation.Clear()
	cancelMessage, err := externalpeer.VerifyCourierMessage(
		cancellation.Cancel,
		publicKey,
		fixture.now.Add(12*time.Second),
	)
	if err != nil || cancelMessage.Kind != externalpeer.CourierCancel {
		t.Fatalf("invalid post-sequence-2 cancel: kind=%d err=%v", cancelMessage.Kind, err)
	}
	if _, err := signer.SignCancellation(
		fixture.now.Add(13*time.Second),
		entropy,
	); err == nil {
		t.Fatal("sequence 3 replay was signed")
	}
}

func TestCancelBeforePeerPermanentlyRefusesSequence2(t *testing.T) {
	t.Parallel()
	fixture := newHostTransactionFixture(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	entropy := nonceEntropy(11, 12, 13, 14)
	signer, initial, err := NewTransactionSigner(
		fixture.input,
		privateKey,
		fixture.now,
		entropy,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	defer initial.Clear()
	cancel, err := signer.SignCancellation(
		fixture.now.Add(5*time.Second),
		entropy,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel.Clear()
	if _, err := signer.SignPeerResponse(
		fixture.peer,
		fixture.now.Add(6*time.Second),
		entropy,
	); err == nil {
		t.Fatal("sequence 2 was signed after pre-peer cancellation")
	}
}

func TestSequentialSignerRejectsTamperedPeerRoleReplayAndExpiry(t *testing.T) {
	t.Parallel()
	fixture := newHostTransactionFixture(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	entropy := nonceEntropy(21, 22, 23, 24)
	signer, initial, err := NewTransactionSigner(
		fixture.input,
		privateKey,
		fixture.now,
		entropy,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	defer initial.Clear()
	tampered := clonePeerPublicArtifacts(fixture.peer)
	tampered.Descriptor[0] ^= 0x01
	if _, err := signer.SignPeerResponse(
		tampered,
		fixture.now.Add(5*time.Second),
		entropy,
	); err == nil {
		t.Fatal("tampered peer descriptor was signed")
	}
	clearPeerArtifacts(&tampered)
	if _, err := signer.SignCancellation(
		fixture.now.Add(externalpeer.MaxCourierLife),
		entropy,
	); err == nil {
		t.Fatal("expired cancellation was signed")
	}
}

func nonceEntropy(values ...byte) *bytes.Reader {
	data := make([]byte, 0, len(values)*32)
	for _, value := range values {
		data = append(data, bytes.Repeat([]byte{value}, 32)...)
	}
	return bytes.NewReader(data)
}

func clonePeerPublicArtifacts(
	value externalpeer.PeerPublicArtifacts,
) externalpeer.PeerPublicArtifacts {
	return externalpeer.PeerPublicArtifacts{
		Descriptor:             append([]byte(nil), value.Descriptor...),
		CADER:                  append([]byte(nil), value.CADER...),
		ServerCertificateDER:   append([]byte(nil), value.ServerCertificateDER...),
		ClientCertificateDER:   append([]byte(nil), value.ClientCertificateDER...),
		OverlayServerPublicKey: append([]byte(nil), value.OverlayServerPublicKey...),
		SystemSSHHostPublicKey: append([]byte(nil), value.SystemSSHHostPublicKey...),
		TransferManifest:       append([]byte(nil), value.TransferManifest...),
	}
}
