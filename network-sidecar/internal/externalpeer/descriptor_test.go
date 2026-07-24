package externalpeer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"testing"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"golang.org/x/crypto/ssh"
)

const (
	testRunID      = "external-peer-test-0001"
	testClientUUID = "11111111-1111-4111-8111-111111111111"
	testPeerUUID   = "22222222-2222-4222-8222-222222222222"
	testClientMAC  = "02:00:00:00:00:11"
	testPeerMAC    = "02:00:00:00:00:22"
)

var (
	testClientIP = netip.MustParseAddr("192.168.64.11")
	testPeerIP   = netip.MustParseAddr("192.168.64.22")
)

type identityFixture struct {
	now              time.Time
	clientIdentity   *ClientIdentity
	clientDescriptor ClientPublicDescriptor
	clientArtifacts  ClientPublicArtifacts
	clientWGPublic   []byte
	peerIdentity     *PeerIdentity
	peerDescriptor   PeerPublicDescriptor
	peerArtifacts    PeerPublicArtifacts
	systemHostPublic []byte
}

func newIdentityFixture(t *testing.T) identityFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(30 * time.Minute)
	clientIdentity, err := NewClientIdentity(testRunID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clientIdentity.Clear)
	clientWGPublic := make([]byte, 32)
	if _, err := rand.Read(clientWGPublic); err != nil {
		t.Fatal(err)
	}
	clientDescriptor, clientArtifacts, err := clientIdentity.PublicArtifacts(ClientDescriptorConfig{
		RunID:              testRunID,
		ExpiresAt:          expires,
		VirtualMacModel:    "VirtualMac2,1",
		PlatformUUID:       testClientUUID,
		ClientIPv4:         testClientIP,
		ClientMAC:          testClientMAC,
		WireGuardPublicKey: clientWGPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, systemHostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(systemHostPrivate) })
	systemHostSigner, err := ssh.NewSignerFromKey(systemHostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	systemHostPublic := systemHostSigner.PublicKey().Marshal()
	peerIdentity, err := NewPeerIdentity(
		now,
		expires,
		testRunID,
		testPeerIP,
		clientArtifacts.TLSClientCSRDER,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peerIdentity.Clear)
	peerDescriptor, peerArtifacts, err := peerIdentity.PublicArtifacts(PeerDescriptorConfig{
		RunID:                    testRunID,
		IssuedAt:                 now,
		ExpiresAt:                expires,
		ClientPlatformUUID:       testClientUUID,
		PeerPlatformUUID:         testPeerUUID,
		ClientIPv4:               testClientIP,
		PeerIPv4:                 testPeerIP,
		ClientMAC:                testClientMAC,
		PeerMAC:                  testPeerMAC,
		ClientWireGuardPublicKey: clientWGPublic,
		ClientOverlayPublicKey:   clientArtifacts.OverlayClientPublicKey,
		Endpoints: []profile.Endpoint{
			{Transport: profile.QUIC, URL: "https://192.168.64.22:22001"},
			{Transport: profile.WSS, URL: "wss://192.168.64.22:22002/kynp"},
			{Transport: profile.TCP, URL: "tcp://192.168.64.22:22003"},
		},
		SystemSSHHostPublicKey: systemHostPublic,
	}, clientDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachPeerTransferManifest(testRunID, &peerArtifacts); err != nil {
		t.Fatal(err)
	}
	return identityFixture{
		now:              now,
		clientIdentity:   clientIdentity,
		clientDescriptor: clientDescriptor,
		clientArtifacts:  clientArtifacts,
		clientWGPublic:   clientWGPublic,
		peerIdentity:     peerIdentity,
		peerDescriptor:   peerDescriptor,
		peerArtifacts:    peerArtifacts,
		systemHostPublic: systemHostPublic,
	}
}

func (fixture identityFixture) clientExpectation() ClientExpectation {
	return ClientExpectation{
		RunID:              testRunID,
		Now:                fixture.now,
		ClientPlatformUUID: testClientUUID,
		ClientIPv4:         testClientIP,
		ClientMAC:          testClientMAC,
		WireGuardPublicKey: fixture.clientWGPublic,
	}
}

func (fixture identityFixture) peerExpectation() PeerExpectation {
	return PeerExpectation{
		RunID:                    testRunID,
		Now:                      fixture.now,
		ClientPlatformUUID:       testClientUUID,
		PeerPlatformUUID:         testPeerUUID,
		ClientIPv4:               testClientIP,
		PeerIPv4:                 testPeerIP,
		ClientMAC:                testClientMAC,
		PeerMAC:                  testPeerMAC,
		ClientWireGuardPublicKey: fixture.clientWGPublic,
		ClientCSRDER:             fixture.clientArtifacts.TLSClientCSRDER,
		OverlayClientPublicKey:   fixture.clientArtifacts.OverlayClientPublicKey,
	}
}

func TestStrictPublicBundleRoundTrip(t *testing.T) {
	fixture := newIdentityFixture(t)
	client, err := DecodeClientPublicDescriptor(
		fixture.clientArtifacts.Descriptor,
		fixture.clientArtifacts,
		fixture.clientExpectation(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if client.RunID != testRunID {
		t.Fatalf("unexpected client run: %q", client.RunID)
	}
	peer, err := DecodePeerPublicDescriptor(
		fixture.peerArtifacts.Descriptor,
		fixture.peerArtifacts,
		fixture.peerExpectation(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if peer.BindInterface != BindInterface ||
		peer.TLSVersion != "1.3" ||
		!peer.MutualTLS ||
		peer.OverlaySSHAddress != "10.88.0.2:22" ||
		peer.SystemSSHProxyAddress != "10.88.0.2:2222" {
		t.Fatalf("unexpected peer descriptor: %#v", peer)
	}
}

func TestDescriptorRejectsUnknownDuplicateLoopbackAndArtifactSwap(t *testing.T) {
	fixture := newIdentityFixture(t)
	unknown := append(
		[]byte(`{"unknown":true,`),
		fixture.clientArtifacts.Descriptor[1:]...,
	)
	if _, err := DecodeClientPublicDescriptor(
		unknown,
		ClientPublicArtifacts{
			Descriptor:             unknown,
			TLSClientCSRDER:        fixture.clientArtifacts.TLSClientCSRDER,
			OverlayClientPublicKey: fixture.clientArtifacts.OverlayClientPublicKey,
		},
		fixture.clientExpectation(),
	); err == nil {
		t.Fatal("unknown field was accepted")
	}
	duplicate := []byte(`{"schema_version":1,"schema_version":1}`)
	if !errorsIs(rejectDuplicateObjectKeys(duplicate), ErrDuplicateJSONKey) {
		t.Fatal("duplicate key was not rejected")
	}
	peer := fixture.peerDescriptor
	peer.PeerEn0PrivateIPv4 = "127.0.0.1"
	if _, err := EncodePeerPublicDescriptor(peer); err == nil {
		t.Fatal("loopback peer address was accepted")
	}
	artifacts := clonePeerArtifacts(fixture.peerArtifacts)
	artifacts.ServerCertificateDER[0] ^= 0xff
	if _, err := DecodePeerPublicDescriptor(
		fixture.peerArtifacts.Descriptor,
		artifacts,
		fixture.peerExpectation(),
	); err == nil {
		t.Fatal("certificate substitution was accepted")
	}
}

func TestClientCertificateMatchesOnlyOriginalCSRKey(t *testing.T) {
	fixture := newIdentityFixture(t)
	if _, err := fixture.clientIdentity.TLSCertificate(
		fixture.peerArtifacts.ClientCertificateDER,
	); err != nil {
		t.Fatal(err)
	}
	other, err := NewClientIdentity(testRunID)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Clear()
	if _, err := other.TLSCertificate(
		fixture.peerArtifacts.ClientCertificateDER,
	); err == nil {
		t.Fatal("foreign client private key matched signed certificate")
	}
}

func TestNoPrivateMaterialAppearsInPublicDescriptors(t *testing.T) {
	fixture := newIdentityFixture(t)
	for _, raw := range [][]byte{
		fixture.clientArtifacts.Descriptor,
		fixture.peerArtifacts.Descriptor,
	} {
		for _, private := range [][]byte{
			fixture.clientIdentity.TLSPrivateKey,
			fixture.clientIdentity.OverlayPrivateKey,
			fixture.peerIdentity.OverlayPrivateKey,
		} {
			if len(private) > 0 &&
				containsBytes(raw, []byte(base64.StdEncoding.EncodeToString(private))) {
				t.Fatal("private material appeared in public descriptor")
			}
		}
	}
}

func containsBytes(haystack, needle []byte) bool {
	return len(needle) != 0 && string(haystack) != "" &&
		len(haystack) >= len(needle) &&
		bytesContains(haystack, needle)
}

func bytesContains(haystack, needle []byte) bool {
	for index := 0; index+len(needle) <= len(haystack); index++ {
		match := true
		for offset := range needle {
			match = match && haystack[index+offset] == needle[offset]
		}
		if match {
			return true
		}
	}
	return false
}

func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		value, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = value.Unwrap()
	}
	return false
}
