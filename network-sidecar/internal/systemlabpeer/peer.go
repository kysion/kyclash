// Package systemlabpeer provides the guest-only peer used by the disposable
// networking-production VM lab.
//
// This package deliberately has no Tauri, macOS privilege, or production
// bootstrap dependency.  It owns one userspace WireGuard device, three
// loopback carriers, and two private echo addresses.  The executable that
// uses it is a lab fixture and must never be copied into a KyClash bundle.
package systemlabpeer

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"github.com/kysion/kyclash/network-sidecar/internal/wgcarrier"
	quicgo "github.com/quic-go/quic-go"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	// EchoPort is part of the disposable lab contract.  It is not a production
	// service port and is reachable only through the userspace tunnel.
	EchoPort uint16 = 8080

	manifestVersion   = 1
	descriptorVersion = 1
	maxDescriptorSize = 32 * 1024
	maxManifestSize   = 8 * 1024
	defaultLifetime   = 24 * time.Hour
	tlsHandshakeLimit = 5 * time.Second
	minCarrierPort    = 20_000
	maxCarrierPort    = 60_000

	peerKeyFile         = "wg-private.key"
	retiredRootKeyFile  = "loopback-trust-root.key"
	rootCertificateFile = "loopback-trust-root.pem"
	tlsKeyFile          = "loopback-leaf.key"
	certificateFile     = "loopback-leaf.pem"
	manifestFile        = "peer-manifest.json"
	carrierEndpointID   = "kyclash-system-lab-peer"
	websocketPath       = "/kynp"
	quicALPN            = "kyclash-network/1"
	guestLabRoot        = "/private/var/tmp/kyclash-networking-vm-lab"
)

var (
	ErrInvalidConfig      = errors.New("invalid system lab peer configuration")
	ErrUnsafeFile         = errors.New("unsafe system lab peer file")
	ErrExistingDescriptor = errors.New("system lab peer descriptor already exists")
	ErrExistingRun        = errors.New("system lab peer private run already exists")
	ErrInvalidDescriptor  = errors.New("invalid system lab peer descriptor")
	ErrPortUnavailable    = errors.New("system lab peer carrier port unavailable")
	ErrParentClosed       = errors.New("system lab peer controller closed")
)

var (
	loopbackHost = netip.MustParseAddr("127.0.0.1")
	peerIPv4     = netip.MustParseAddr("10.88.0.2")
	peerIPv6     = netip.MustParseAddr("fd00:88::2")
	clientIPv4   = netip.MustParseAddr("10.88.0.1")
	clientIPv6   = netip.MustParseAddr("fd00:88::1")
)

// Config identifies one disposable run.  PrivateDir must be a newly-created
// 0700 directory (normally beneath /var/tmp in the guest).  The client key is
// a 32-byte raw Curve25519 public key in a separate 0600 regular file.
type Config struct {
	RunID               string
	ClientPublicKeyPath string
	PrivateDir          string
	DescriptorPath      string
	ManifestPath        string
	// Supplying all certificate paths lets the guest trust fixture provide its
	// exact root/leaf pair. Empty values create a fresh pair in PrivateDir.
	RootCertificatePath string
	CertificatePath     string
	TLSPrivateKeyPath   string
	ExpiresAt           time.Time
	externalTLSFixture  bool
}

// Ports are persisted before the descriptor is published.  A later run with
// the same private manifest must bind exactly these ports; it never silently
// chooses replacement ports.
type Ports struct {
	QUIC uint16 `json:"quic"`
	WSS  uint16 `json:"wss"`
	TCP  uint16 `json:"tcp"`
}

// Descriptor is the only public output of the peer.  It intentionally omits
// private file contents and private key material.  JSON decoding is strict so
// a future producer cannot accidentally add an authority-bearing field.
type Descriptor struct {
	SchemaVersion     uint8              `json:"schema_version"`
	RunID             string             `json:"run_id"`
	PeerPublicKey     string             `json:"peer_public_key"`
	ClientPublicKey   string             `json:"client_public_key"`
	Endpoints         []profile.Endpoint `json:"endpoints"`
	EchoAddresses     []string           `json:"echo_addresses"`
	CertificateSHA256 string             `json:"certificate_sha256"`
	CertificatePath   string             `json:"certificate_path"`
	ExpiresAt         int64              `json:"expires_at"`
}

// Manifest is private run state.  Paths are fixed basenames and are resolved
// below PrivateDir, which prevents a manifest from redirecting key reads.
type Manifest struct {
	SchemaVersion         uint8  `json:"schema_version"`
	RunID                 string `json:"run_id"`
	Ports                 Ports  `json:"ports"`
	PeerKeyFile           string `json:"peer_key_file"`
	TLSKeyFile            string `json:"tls_key_file"`
	CertificateFile       string `json:"certificate_file"`
	RootCertificateFile   string `json:"root_certificate_file"`
	RootCertificateSHA256 string `json:"root_certificate_sha256"`
	ClientKeySHA256       string `json:"client_key_sha256"`
	PeerPublicKey         string `json:"peer_public_key"`
	CertificateSHA256     string `json:"certificate_sha256"`
	ExpiresAt             int64  `json:"expires_at"`
}

type Peer struct {
	ctx            context.Context
	cancel         context.CancelFunc
	done           chan error
	ready          chan struct{}
	closeOnce      sync.Once
	wg             sync.WaitGroup
	mu             sync.Mutex
	closed         bool
	active         *trackedCarrier
	deviceUp       bool
	board          *wgcarrier.Switchboard
	wireGuard      *device.Device
	network        *netstack.Net
	listeners      []*carrierListener
	echoListeners  []net.Listener
	descriptorPath string
	descriptorHash string
	descriptorInfo os.FileInfo
	descriptor     Descriptor
	privateDir     string
	attachErrors   chan error
	detachReasons  chan error
	wssConnections *wssRegistry
}

type peerState struct {
	manifest     Manifest
	privateKey   []byte
	publicKey    []byte
	tlsKey       any
	certificate  tls.Certificate
	certDER      []byte
	rootCertDER  []byte
	certHash     string
	rootCertHash string
	clientKey    []byte
}

type carrierListener struct {
	transport profile.Transport
	endpoint  profile.Endpoint
	accept    func(context.Context) (carrier.Carrier, error)
	close     func() error
}

type trackedCarrier struct {
	carrier.Carrier
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	reason error
}

func (value *trackedCarrier) signalClosed() {
	value.once.Do(func() { close(value.closed) })
}

func (value *trackedCarrier) setReason(err error) {
	value.mu.Lock()
	value.reason = err
	value.mu.Unlock()
}

func (value *trackedCarrier) getReason() error {
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.reason
}

func (value *trackedCarrier) Receive(ctx context.Context) ([]byte, error) {
	packet, err := value.Carrier.Receive(ctx)
	if err != nil {
		value.setReason(err)
		value.signalClosed()
	}
	return packet, err
}

func (value *trackedCarrier) Close() error {
	err := value.Carrier.Close()
	if err != nil {
		value.setReason(err)
	}
	value.signalClosed()
	return err
}

func (value *trackedCarrier) Probe(ctx context.Context) (time.Duration, error) {
	prober, ok := value.Carrier.(carrier.Prober)
	if !ok {
		return 0, carrier.ErrProbeUnavailable
	}
	return prober.Probe(ctx)
}

// Start creates one peer and publishes its descriptor only after all three
// loopback listeners, the single dual-stack userspace device, and both echo
// listeners are ready.
func Start(parent context.Context, config Config) (*Peer, error) {
	if parent == nil {
		parent = context.Background()
	}
	config, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	if err := rejectExistingDescriptor(config.DescriptorPath); err != nil {
		return nil, err
	}
	state, err := loadOrCreateState(config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	peer := &Peer{
		ctx:            ctx,
		cancel:         cancel,
		done:           make(chan error, 1),
		ready:          make(chan struct{}),
		descriptorPath: config.DescriptorPath,
		privateDir:     config.PrivateDir,
		attachErrors:   make(chan error, 8),
		detachReasons:  make(chan error, 8),
	}
	cleanup := func() {
		cancel()
		closeCarrierListeners(peer.listeners)
		closeNetListeners(peer.echoListeners)
		if peer.wireGuard != nil {
			peer.wireGuard.Close()
		}
		if peer.board != nil {
			_ = peer.board.Shutdown()
		}
		clear(state.privateKey)
		clear(state.clientKey)
		releaseSensitiveKey(&state.tlsKey)
	}

	listeners, wssConnections, err := openCarrierListeners(ctx, state.manifest.Ports, state.certificate)
	if err != nil {
		cleanup()
		return nil, err
	}
	peer.listeners = listeners
	peer.wssConnections = wssConnections

	tunnel, network, err := netstack.CreateNetTUN([]netip.Addr{peerIPv4, peerIPv6}, nil, profile.TunnelMTU)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("create dual-stack peer tunnel: %w", err)
	}
	board := wgcarrier.NewSwitchboard()
	bind, err := wgcarrier.NewBind(board, carrierEndpointID)
	if err != nil {
		_ = tunnel.Close()
		cleanup()
		return nil, err
	}
	wireGuard := device.NewDevice(tunnel, bind, device.NewLogger(device.LogLevelSilent, ""))
	if err := wireGuard.Down(); err != nil {
		wireGuard.Close()
		cleanup()
		return nil, fmt.Errorf("quiesce peer tunnel: %w", err)
	}
	if err := configurePeer(wireGuard, state.privateKey, state.clientKey); err != nil {
		wireGuard.Close()
		cleanup()
		return nil, err
	}
	if err := wireGuard.Down(); err != nil {
		wireGuard.Close()
		cleanup()
		return nil, fmt.Errorf("quiesce configured peer tunnel: %w", err)
	}
	clear(state.privateKey)
	peer.board, peer.wireGuard, peer.network = board, wireGuard, network

	echoListeners, err := openEchoListeners(network)
	if err != nil {
		cleanup()
		return nil, err
	}
	peer.echoListeners = echoListeners

	descriptor := makeDescriptor(config, state, listeners)
	descriptorBytes, err := marshalDescriptor(descriptor)
	if err != nil {
		cleanup()
		return nil, err
	}
	descriptorInfo, err := publishDescriptor(config.DescriptorPath, descriptorBytes)
	if err != nil {
		cleanup()
		return nil, err
	}
	peer.descriptor = descriptor
	peer.descriptorHash = hex.EncodeToString(sum256(descriptorBytes))
	peer.descriptorInfo = descriptorInfo
	close(peer.ready)

	for _, listener := range peer.listeners {
		peer.wg.Add(1)
		go peer.acceptLoop(listener)
	}
	for _, listener := range peer.echoListeners {
		peer.wg.Add(1)
		go peer.echoLoop(listener)
	}
	// lifecycle is deliberately not counted in peer.wg: it waits for the
	// listener/echo goroutines that it is responsible for shutting down.
	go peer.lifecycle()
	return peer, nil
}

func (peer *Peer) lifecycle() {
	<-peer.ctx.Done()
	peer.shutdownRuntime()
	peer.wg.Wait()
	peer.removeDescriptor()
	select {
	case peer.done <- nil:
	default:
	}
}

// WaitReady waits until the public descriptor is atomically visible.
func (peer *Peer) WaitReady(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-peer.ready:
		return nil
	case <-peer.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (peer *Peer) Done() <-chan error { return peer.done }

func (peer *Peer) Descriptor() Descriptor {
	value := peer.descriptor
	value.Endpoints = append([]profile.Endpoint(nil), value.Endpoints...)
	value.EchoAddresses = append([]string(nil), value.EchoAddresses...)
	return value
}

// Close is idempotent and removes only the exact descriptor this run
// published.  Private identity files remain for the bounded reboot matrix;
// the caller owns their final exact cleanup.
func (peer *Peer) Close() error {
	peer.closeOnce.Do(func() {
		peer.mu.Lock()
		peer.closed = true
		peer.mu.Unlock()
		peer.cancel()
	})
	return nil
}

func (peer *Peer) shutdownRuntime() {
	peer.mu.Lock()
	wireGuard := peer.wireGuard
	board := peer.board
	// Publish the terminal state before closing the device. The carrier
	// watcher can otherwise try to acquire this mutex while wireguard-go waits
	// for that watcher during Close.
	peer.active = nil
	peer.deviceUp = false
	peer.mu.Unlock()
	if board != nil {
		_ = board.Shutdown()
	}
	if wireGuard != nil {
		wireGuard.Close()
	}
	closeCarrierListeners(peer.listeners)
	closeNetListeners(peer.echoListeners)
}

func (peer *Peer) removeDescriptor() {
	if peer.descriptorPath == "" || peer.descriptorInfo == nil {
		return
	}
	info, err := os.Lstat(peer.descriptorPath)
	if err != nil {
		return
	}
	if !os.SameFile(peer.descriptorInfo, info) || !safeOwnedRegularInfo(info, 0o644) || linkCount(info) != 1 {
		return
	}
	file, err := os.OpenFile(peer.descriptorPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(peer.descriptorInfo, openedInfo) || !os.SameFile(info, openedInfo) {
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDescriptorSize+1))
	if err != nil || len(data) > maxDescriptorSize || hex.EncodeToString(sum256(data)) != peer.descriptorHash {
		clear(data)
		return
	}
	clear(data)
	// Re-stat after the fd read. A same-content replacement gets a different
	// inode and is left untouched; the owned parent directory then makes this
	// final unlink race bounded to this run's identity.
	latest, err := os.Lstat(peer.descriptorPath)
	if err != nil || !os.SameFile(peer.descriptorInfo, latest) || linkCount(latest) != 1 {
		return
	}
	_ = os.Remove(peer.descriptorPath)
}

func (peer *Peer) acceptLoop(listener *carrierListener) {
	defer peer.wg.Done()
	for {
		candidate, err := listener.accept(peer.ctx)
		if err != nil {
			if peer.ctx.Err() != nil {
				return
			}
			continue
		}
		if err := peer.attach(candidate); err != nil {
			select {
			case peer.attachErrors <- err:
			default:
			}
			_ = candidate.Close()
		}
	}
}

func (peer *Peer) attach(candidate carrier.Carrier) error {
	if candidate == nil {
		return ErrInvalidConfig
	}
	tracked := &trackedCarrier{Carrier: candidate, closed: make(chan struct{})}
	peer.mu.Lock()
	if peer.closed || peer.ctx.Err() != nil || peer.active != nil || peer.board == nil || peer.wireGuard == nil {
		peer.mu.Unlock()
		return net.ErrClosed
	}
	if err := peer.board.Attach(tracked); err != nil {
		peer.mu.Unlock()
		return err
	}
	if err := peer.wireGuard.Up(); err != nil {
		_ = peer.board.Detach()
		peer.mu.Unlock()
		return err
	}
	peer.active = tracked
	peer.deviceUp = true
	peer.mu.Unlock()

	peer.wg.Add(1)
	go func() {
		defer peer.wg.Done()
		select {
		case <-tracked.closed:
			if reason := tracked.getReason(); reason != nil {
				select {
				case peer.detachReasons <- reason:
				default:
				}
			}
			peer.detach(tracked)
		case <-peer.ctx.Done():
		}
	}()
	return nil
}

func (peer *Peer) detach(target *trackedCarrier) {
	peer.mu.Lock()
	if peer.active != target {
		peer.mu.Unlock()
		return
	}
	peer.active = nil
	if peer.wireGuard != nil && peer.deviceUp {
		_ = peer.wireGuard.Down()
		peer.deviceUp = false
	}
	if peer.board != nil {
		_ = peer.board.Detach()
	}
	peer.mu.Unlock()
}

func (peer *Peer) echoLoop(listener net.Listener) {
	defer peer.wg.Done()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if peer.ctx.Err() != nil {
				return
			}
			continue
		}
		peer.wg.Add(1)
		go func() {
			defer peer.wg.Done()
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}()
	}
}

func normalizeConfig(config Config) (Config, error) {
	if !validRunID(config.RunID) || config.ClientPublicKeyPath == "" || config.PrivateDir == "" || config.DescriptorPath == "" {
		return Config{}, ErrInvalidConfig
	}
	var err error
	providedTLSPaths := config.RootCertificatePath != "" || config.CertificatePath != "" || config.TLSPrivateKeyPath != ""
	if providedTLSPaths && (config.RootCertificatePath == "" || config.CertificatePath == "" || config.TLSPrivateKeyPath == "") {
		return Config{}, ErrInvalidConfig
	}
	config.externalTLSFixture = providedTLSPaths
	config.ClientPublicKeyPath, err = filepath.Abs(config.ClientPublicKeyPath)
	if err != nil {
		return Config{}, ErrInvalidConfig
	}
	config.PrivateDir, err = filepath.Abs(config.PrivateDir)
	if err != nil {
		return Config{}, ErrInvalidConfig
	}
	config.DescriptorPath, err = filepath.Abs(config.DescriptorPath)
	if err != nil {
		return Config{}, ErrInvalidConfig
	}
	if config.ManifestPath == "" {
		config.ManifestPath = filepath.Join(config.PrivateDir, manifestFile)
	} else if config.ManifestPath, err = filepath.Abs(config.ManifestPath); err != nil {
		return Config{}, ErrInvalidConfig
	}
	if filepath.Dir(config.ManifestPath) != config.PrivateDir || filepath.Base(config.ManifestPath) != manifestFile {
		return Config{}, ErrInvalidConfig
	}
	config.RootCertificatePath, err = normalizePrivateArtifactPath(config.PrivateDir, config.RootCertificatePath, rootCertificateFile)
	if err != nil {
		return Config{}, err
	}
	config.CertificatePath, err = normalizePrivateArtifactPath(config.PrivateDir, config.CertificatePath, certificateFile)
	if err != nil {
		return Config{}, err
	}
	config.TLSPrivateKeyPath, err = normalizePrivateArtifactPath(config.PrivateDir, config.TLSPrivateKeyPath, tlsKeyFile)
	if err != nil {
		return Config{}, err
	}
	if config.ExpiresAt.IsZero() {
		config.ExpiresAt = time.Now().UTC().Add(defaultLifetime)
	}
	now := time.Now().UTC()
	if !config.ExpiresAt.After(now) || config.ExpiresAt.After(now.Add(defaultLifetime)) {
		return Config{}, ErrInvalidConfig
	}
	if runtime.GOOS == "darwin" &&
		os.Getenv("KYCLASH_RUNNER_ENVIRONMENT") == "local-virtualization-framework" &&
		os.Getenv("KYCLASH_VM_LAB_CONFIRM") == "authorized-kyclash-virtualization-framework-vm" &&
		os.Getenv("KYCLASH_RUNTIME_TARGET") == "kyclash-macos-lab-work" {
		expectedRoot := filepath.Join(guestLabRoot, config.RunID)
		expected := map[string]string{
			"private directory": expectedRoot,
			"client public key": filepath.Join(expectedRoot, "client-public.key"),
			"descriptor":        filepath.Join(expectedRoot, "guest-descriptor.json"),
			"manifest":          filepath.Join(expectedRoot, manifestFile),
			"peer private key":  filepath.Join(expectedRoot, peerKeyFile),
			"root certificate":  filepath.Join(expectedRoot, rootCertificateFile),
			"leaf certificate":  filepath.Join(expectedRoot, certificateFile),
			"leaf private key":  filepath.Join(expectedRoot, tlsKeyFile),
		}
		actual := map[string]string{
			"private directory": config.PrivateDir,
			"client public key": config.ClientPublicKeyPath,
			"descriptor":        config.DescriptorPath,
			"manifest":          config.ManifestPath,
			"peer private key":  filepath.Join(config.PrivateDir, peerKeyFile),
			"root certificate":  config.RootCertificatePath,
			"leaf certificate":  config.CertificatePath,
			"leaf private key":  config.TLSPrivateKeyPath,
		}
		for label, expectedPath := range expected {
			if filepath.Clean(actual[label]) != expectedPath {
				return Config{}, fmt.Errorf("%w: %s path is not run-bound", ErrInvalidConfig, label)
			}
		}
	}
	return config, nil
}

func normalizePrivateArtifactPath(privateDir, value, defaultBase string) (string, error) {
	if value == "" {
		return filepath.Join(privateDir, defaultBase), nil
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", ErrInvalidConfig
	}
	relative, err := filepath.Rel(privateDir, absolute)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.Base(relative) != filepath.Base(value) {
		return "", ErrInvalidConfig
	}
	return absolute, nil
}

func validRunID(value string) bool {
	if len(value) != 16 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func rejectExistingDescriptor(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return ErrUnsafeFile
		}
		return ErrExistingDescriptor
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect descriptor: %w", err)
	}
	return nil
}

func loadOrCreateState(config Config) (peerState, error) {
	if err := ensurePrivateDir(config.PrivateDir); err != nil {
		return peerState{}, err
	}
	if info, err := os.Lstat(filepath.Join(config.PrivateDir, retiredRootKeyFile)); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return peerState{}, ErrUnsafeFile
		}
		// A previous implementation persisted the CA signing key. Never reuse
		// or silently leave that authority in a production-shaped lab run.
		return peerState{}, ErrExistingRun
	} else if !errors.Is(err, os.ErrNotExist) {
		return peerState{}, fmt.Errorf("inspect retired root key: %w", err)
	}
	clientKey, err := readRawPublicKey(config.ClientPublicKeyPath)
	if err != nil {
		return peerState{}, err
	}
	manifestInfo, manifestErr := os.Lstat(config.ManifestPath)
	if manifestErr == nil && manifestInfo.Mode()&os.ModeSymlink != 0 {
		return peerState{}, ErrUnsafeFile
	}
	if manifestErr == nil {
		manifest, err := readManifest(config.ManifestPath)
		if err != nil {
			return peerState{}, err
		}
		if manifest.RunID != config.RunID || manifest.ClientKeySHA256 != hashHex(clientKey) || manifest.ExpiresAt <= time.Now().Unix() || manifest.ExpiresAt > time.Now().Add(defaultLifetime).Unix() || !validPorts(manifest.Ports) {
			return peerState{}, ErrInvalidConfig
		}
		state, err := readPersistedState(config, manifest, clientKey)
		if err != nil {
			return peerState{}, err
		}
		return state, nil
	}
	if !errors.Is(manifestErr, os.ErrNotExist) {
		return peerState{}, fmt.Errorf("inspect manifest: %w", manifestErr)
	}
	for _, name := range []string{peerKeyFile} {
		if _, err := os.Lstat(filepath.Join(config.PrivateDir, name)); err == nil {
			return peerState{}, ErrExistingRun
		} else if !errors.Is(err, os.ErrNotExist) {
			return peerState{}, fmt.Errorf("inspect private state: %w", err)
		}
	}
	if config.externalTLSFixture {
		return createStateWithFixture(config, clientKey)
	}
	for _, name := range []string{rootCertificateFile, tlsKeyFile, certificateFile} {
		if _, err := os.Lstat(filepath.Join(config.PrivateDir, name)); err == nil {
			return peerState{}, ErrExistingRun
		} else if !errors.Is(err, os.ErrNotExist) {
			return peerState{}, fmt.Errorf("inspect private state: %w", err)
		}
	}
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return peerState{}, err
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		clear(privateKey)
		return peerState{}, err
	}
	tlsPublic, tlsPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		clear(privateKey)
		clear(publicKey)
		return peerState{}, err
	}
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		clear(privateKey)
		clear(publicKey)
		clear(tlsPrivate)
		clear(rootPrivate)
		return peerState{}, err
	}
	rootDER, certDER, err := makeCertificateChain(rootPublic, rootPrivate, tlsPublic, tlsPrivate)
	// The root key is needed only for this one leaf-signing operation. Retain
	// no on-disk copy: restart needs the root certificate and leaf key, not the
	// CA signing authority.
	clear(rootPrivate)
	if err != nil {
		clear(privateKey)
		clear(publicKey)
		clear(tlsPrivate)
		return peerState{}, err
	}
	if err := writePrivateFile(filepath.Join(config.PrivateDir, peerKeyFile), privateKey, 0o600); err != nil {
		clear(privateKey)
		clear(publicKey)
		clear(tlsPrivate)
		return peerState{}, err
	}
	if err := writePrivateFile(filepath.Join(config.PrivateDir, tlsKeyFile), tlsPrivate, 0o600); err != nil {
		_ = os.Remove(filepath.Join(config.PrivateDir, peerKeyFile))
		_ = os.Remove(filepath.Join(config.PrivateDir, tlsKeyFile))
		clear(privateKey)
		clear(publicKey)
		clear(tlsPrivate)
		return peerState{}, err
	}
	rootPEM := pemEncodeCertificate(rootDER)
	leafPEM := pemEncodeCertificate(certDER)
	if err := writePrivateFile(filepath.Join(config.PrivateDir, rootCertificateFile), rootPEM, 0o600); err != nil {
		_ = os.Remove(filepath.Join(config.PrivateDir, peerKeyFile))
		_ = os.Remove(filepath.Join(config.PrivateDir, tlsKeyFile))
		clear(privateKey)
		clear(publicKey)
		clear(tlsPrivate)
		return peerState{}, err
	}
	if err := writePrivateFile(filepath.Join(config.PrivateDir, certificateFile), leafPEM, 0o600); err != nil {
		_ = os.Remove(filepath.Join(config.PrivateDir, peerKeyFile))
		_ = os.Remove(filepath.Join(config.PrivateDir, tlsKeyFile))
		_ = os.Remove(filepath.Join(config.PrivateDir, rootCertificateFile))
		clear(privateKey)
		clear(publicKey)
		clear(tlsPrivate)
		return peerState{}, err
	}
	ports, err := choosePorts()
	if err != nil {
		clear(privateKey)
		clear(publicKey)
		clear(tlsPrivate)
		return peerState{}, err
	}
	manifest := Manifest{
		SchemaVersion:         manifestVersion,
		RunID:                 config.RunID,
		Ports:                 ports,
		PeerKeyFile:           peerKeyFile,
		TLSKeyFile:            tlsKeyFile,
		CertificateFile:       certificateFile,
		RootCertificateFile:   rootCertificateFile,
		RootCertificateSHA256: hashHex(rootDER),
		ClientKeySHA256:       hashHex(clientKey),
		PeerPublicKey:         base64.StdEncoding.EncodeToString(publicKey),
		CertificateSHA256:     hashHex(certDER),
		ExpiresAt:             config.ExpiresAt.Unix(),
	}
	if err := writeManifest(config.ManifestPath, manifest); err != nil {
		_ = os.Remove(filepath.Join(config.PrivateDir, peerKeyFile))
		_ = os.Remove(filepath.Join(config.PrivateDir, tlsKeyFile))
		_ = os.Remove(filepath.Join(config.PrivateDir, rootCertificateFile))
		_ = os.Remove(filepath.Join(config.PrivateDir, certificateFile))
		clear(privateKey)
		clear(publicKey)
		clear(tlsPrivate)
		return peerState{}, err
	}
	return peerState{manifest: manifest, privateKey: privateKey, publicKey: publicKey, tlsKey: tlsPrivate, certificate: tls.Certificate{Certificate: [][]byte{certDER, rootDER}, PrivateKey: tlsPrivate}, certDER: certDER, rootCertDER: rootDER, certHash: hashHex(certDER), rootCertHash: hashHex(rootDER), clientKey: clientKey}, nil
}

func createStateWithFixture(config Config, clientKey []byte) (peerState, error) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return peerState{}, err
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		clear(privateKey)
		return peerState{}, err
	}
	rootPEM, err := readPrivateFile(config.RootCertificatePath, 0)
	if err != nil {
		clear(privateKey)
		clear(publicKey)
		return peerState{}, err
	}
	leafPEM, err := readPrivateFile(config.CertificatePath, 0)
	if err != nil {
		clear(privateKey)
		clear(publicKey)
		clear(rootPEM)
		return peerState{}, err
	}
	keyBytes, err := readPrivateFile(config.TLSPrivateKeyPath, 0)
	if err != nil {
		clear(privateKey)
		clear(publicKey)
		clear(rootPEM)
		clear(leafPEM)
		return peerState{}, err
	}
	rootDER, err := parsePEMCertificate(rootPEM)
	if err != nil {
		clear(privateKey)
		clear(publicKey)
		clear(rootPEM)
		clear(leafPEM)
		clear(keyBytes)
		return peerState{}, err
	}
	leafDER, err := parsePEMCertificate(leafPEM)
	if err != nil || validateCertificateChain(rootDER, leafDER) != nil {
		clear(privateKey)
		clear(publicKey)
		clear(rootPEM)
		clear(leafPEM)
		clear(keyBytes)
		clear(rootDER)
		clear(leafDER)
		return peerState{}, ErrInvalidConfig
	}
	leafCertificate, err := x509.ParseCertificate(leafDER)
	if err != nil || config.ExpiresAt.Unix() >= leafCertificate.NotAfter.Unix() {
		clear(privateKey)
		clear(publicKey)
		clear(rootPEM)
		clear(leafPEM)
		clear(keyBytes)
		clear(rootDER)
		clear(leafDER)
		return peerState{}, ErrInvalidConfig
	}
	tlsPrivate, err := parseTLSPrivateKey(keyBytes)
	clear(keyBytes)
	clear(rootPEM)
	clear(leafPEM)
	if err != nil || !privateKeyMatchesCertificate(tlsPrivate, leafDER) {
		releaseSensitiveKey(&tlsPrivate)
		clear(privateKey)
		clear(publicKey)
		clear(rootDER)
		clear(leafDER)
		return peerState{}, ErrInvalidConfig
	}
	ports, err := choosePorts()
	if err != nil {
		releaseSensitiveKey(&tlsPrivate)
		clear(privateKey)
		clear(publicKey)
		clear(rootDER)
		clear(leafDER)
		return peerState{}, err
	}
	if err := writePrivateFile(filepath.Join(config.PrivateDir, peerKeyFile), privateKey, 0o600); err != nil {
		releaseSensitiveKey(&tlsPrivate)
		clear(privateKey)
		clear(publicKey)
		clear(rootDER)
		clear(leafDER)
		return peerState{}, err
	}
	manifest := Manifest{
		SchemaVersion:         manifestVersion,
		RunID:                 config.RunID,
		Ports:                 ports,
		PeerKeyFile:           peerKeyFile,
		TLSKeyFile:            filepath.Base(config.TLSPrivateKeyPath),
		CertificateFile:       filepath.Base(config.CertificatePath),
		RootCertificateFile:   filepath.Base(config.RootCertificatePath),
		RootCertificateSHA256: hashHex(rootDER),
		ClientKeySHA256:       hashHex(clientKey),
		PeerPublicKey:         base64.StdEncoding.EncodeToString(publicKey),
		CertificateSHA256:     hashHex(leafDER),
		ExpiresAt:             config.ExpiresAt.Unix(),
	}
	if err := writeManifest(config.ManifestPath, manifest); err != nil {
		_ = os.Remove(filepath.Join(config.PrivateDir, peerKeyFile))
		releaseSensitiveKey(&tlsPrivate)
		clear(privateKey)
		clear(publicKey)
		clear(rootDER)
		clear(leafDER)
		return peerState{}, err
	}
	return peerState{manifest: manifest, privateKey: privateKey, publicKey: publicKey, tlsKey: tlsPrivate, certificate: tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: tlsPrivate}, certDER: leafDER, rootCertDER: rootDER, certHash: hashHex(leafDER), rootCertHash: hashHex(rootDER), clientKey: clientKey}, nil
}

func parseTLSPrivateKey(data []byte) (any, error) {
	if len(data) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(append([]byte(nil), data...)), nil
	}
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, ErrInvalidConfig
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes); rsaErr == nil {
			return rsaKey, nil
		}
		return nil, ErrInvalidConfig
	}
	return key, nil
}

func privateKeyMatchesCertificate(privateKey any, leafDER []byte) bool {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil || privateKey == nil {
		return false
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return false
	}
	public := signer.Public()
	left, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return false
	}
	right, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	return err == nil && string(left) == string(right)
}

func clearSensitiveKey(key any) {
	switch value := key.(type) {
	case []byte:
		clear(value)
	case ed25519.PrivateKey:
		clear(value)
	}
}

// releaseSensitiveKey makes ownership explicit on rejected fixture paths.
// Ed25519 bytes are cleared; RSA implementations do not expose a safe
// complete zeroization contract, so their reference is dropped immediately
// and never retained in a returned state.
func releaseSensitiveKey(key *any) {
	if key == nil || *key == nil {
		return
	}
	clearSensitiveKey(*key)
	*key = nil
}

func readPersistedState(config Config, manifest Manifest, clientKey []byte) (peerState, error) {
	if manifest.PeerKeyFile != peerKeyFile || manifest.TLSKeyFile == "" || manifest.CertificateFile == "" || manifest.RootCertificateFile == "" || !validHexHash(manifest.ClientKeySHA256) || !validHexHash(manifest.CertificateSHA256) || !validHexHash(manifest.RootCertificateSHA256) || !validBase64Key(manifest.PeerPublicKey) {
		return peerState{}, ErrInvalidConfig
	}
	for _, name := range []string{manifest.TLSKeyFile, manifest.CertificateFile, manifest.RootCertificateFile} {
		if name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsRune(name, filepath.Separator) {
			return peerState{}, ErrInvalidConfig
		}
	}
	if manifest.TLSKeyFile != filepath.Base(config.TLSPrivateKeyPath) || manifest.CertificateFile != filepath.Base(config.CertificatePath) || manifest.RootCertificateFile != filepath.Base(config.RootCertificatePath) {
		return peerState{}, ErrInvalidConfig
	}
	privateKey, err := readPrivateFile(filepath.Join(config.PrivateDir, peerKeyFile), 32)
	if err != nil {
		return peerState{}, err
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil || !bytesEqualBase64(publicKey, manifest.PeerPublicKey) {
		clear(privateKey)
		clear(publicKey)
		return peerState{}, ErrInvalidConfig
	}
	tlsBytes, err := readPrivateFile(filepath.Join(config.PrivateDir, manifest.TLSKeyFile), 0)
	if err != nil {
		clear(privateKey)
		clear(publicKey)
		return peerState{}, err
	}
	rootPEM, err := readPrivateFile(filepath.Join(config.PrivateDir, manifest.RootCertificateFile), 0)
	if err != nil {
		clear(privateKey)
		clear(publicKey)
		clear(tlsBytes)
		return peerState{}, err
	}
	leafPEM, err := readPrivateFile(filepath.Join(config.PrivateDir, manifest.CertificateFile), 0)
	if err != nil {
		clear(privateKey)
		clear(publicKey)
		clear(tlsBytes)
		clear(rootPEM)
		return peerState{}, err
	}
	rootDER, err := parsePEMCertificate(rootPEM)
	if err != nil || hashHex(rootDER) != manifest.RootCertificateSHA256 {
		clear(privateKey)
		clear(publicKey)
		clear(tlsBytes)
		clear(rootPEM)
		clear(leafPEM)
		return peerState{}, ErrInvalidConfig
	}
	certDER, err := parsePEMCertificate(leafPEM)
	if err != nil || hashHex(certDER) != manifest.CertificateSHA256 {
		clear(privateKey)
		clear(publicKey)
		clear(tlsBytes)
		clear(rootPEM)
		clear(leafPEM)
		clear(rootDER)
		return peerState{}, ErrInvalidConfig
	}
	if err := validateCertificateChain(rootDER, certDER); err != nil {
		clear(privateKey)
		clear(publicKey)
		clear(tlsBytes)
		clear(rootPEM)
		clear(leafPEM)
		clear(rootDER)
		clear(certDER)
		return peerState{}, err
	}
	tlsPrivate, err := parseTLSPrivateKey(tlsBytes)
	clear(tlsBytes)
	clear(rootPEM)
	clear(leafPEM)
	if err != nil {
		releaseSensitiveKey(&tlsPrivate)
		clear(privateKey)
		clear(publicKey)
		clear(rootDER)
		clear(certDER)
		return peerState{}, ErrInvalidConfig
	}
	certificate, err := x509.ParseCertificate(certDER)
	if err != nil || !certificate.NotAfter.After(time.Now()) || manifest.ExpiresAt >= certificate.NotAfter.Unix() || manifest.ExpiresAt > time.Now().Add(defaultLifetime).Unix() {
		clear(privateKey)
		clear(publicKey)
		releaseSensitiveKey(&tlsPrivate)
		clear(rootDER)
		clear(certDER)
		return peerState{}, ErrInvalidConfig
	}
	if err != nil || !privateKeyMatchesCertificate(tlsPrivate, certDER) || hashHex(clientKey) != manifest.ClientKeySHA256 {
		clear(privateKey)
		clear(publicKey)
		releaseSensitiveKey(&tlsPrivate)
		clear(rootDER)
		clear(certDER)
		return peerState{}, ErrInvalidConfig
	}
	return peerState{manifest: manifest, privateKey: privateKey, publicKey: publicKey, tlsKey: tlsPrivate, certificate: tls.Certificate{Certificate: [][]byte{certDER, rootDER}, PrivateKey: tlsPrivate}, certDER: certDER, rootCertDER: rootDER, certHash: hashHex(certDER), rootCertHash: hashHex(rootDER), clientKey: clientKey}, nil
}

func makeCertificateChain(rootPublic ed25519.PublicKey, rootPrivate ed25519.PrivateKey, leafPublic ed25519.PublicKey, leafPrivate ed25519.PrivateKey) ([]byte, []byte, error) {
	now := time.Now().UTC()
	rootTemplate := &x509.Certificate{
		SerialNumber:          new(big.Int).SetInt64(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "KyClash VM lab trust root"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(defaultLifetime),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		return nil, nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          new(big.Int).SetInt64(time.Now().UnixNano() + 1),
		Subject:               pkix.Name{CommonName: loopbackHost.String()},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(defaultLifetime),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{loopbackHost.AsSlice()},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, leafPublic, rootPrivate)
	if err != nil {
		clear(rootDER)
		return nil, nil, err
	}
	_ = leafPrivate // retained by the caller as the TLS private key
	return rootDER, leafDER, nil
}

func pemEncodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func parsePEMCertificate(data []byte) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, ErrInvalidConfig
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, ErrInvalidConfig
	}
	return append([]byte(nil), block.Bytes...), nil
}

func validateCertificateChain(rootDER, leafDER []byte) error {
	root, err := x509.ParseCertificate(rootDER)
	if err != nil || !root.IsCA || !root.BasicConstraintsValid || root.Subject.String() != root.Issuer.String() || root.CheckSignatureFrom(root) != nil || !root.NotAfter.After(time.Now()) {
		return ErrInvalidConfig
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil || leaf.IsCA || !leaf.BasicConstraintsValid || len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(loopbackHost.AsSlice()) || !leaf.NotAfter.After(time.Now()) || leaf.NotAfter.After(root.NotAfter) {
		return ErrInvalidConfig
	}
	serverAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		return ErrInvalidConfig
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: loopbackHost.String(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return ErrInvalidConfig
	}
	return nil
}

func configurePeer(wireGuard *device.Device, privateKey, clientKey []byte) error {
	if len(privateKey) != 32 || len(clientKey) != 32 {
		return ErrInvalidConfig
	}
	var configuration strings.Builder
	// The peer's allowed source addresses are the client's tunnel addresses;
	// the local private echo addresses are installed on this side's netstack.
	fmt.Fprintf(&configuration, "private_key=%s\nreplace_peers=true\npublic_key=%s\nprotocol_version=1\nreplace_allowed_ips=true\nallowed_ip=%s/32\nallowed_ip=%s/128\nendpoint=%s\n", hex.EncodeToString(privateKey), hex.EncodeToString(clientKey), clientIPv4, clientIPv6, carrierEndpointID)
	if err := wireGuard.IpcSet(configuration.String()); err != nil {
		configuration.Reset()
		return fmt.Errorf("configure system lab peer: %w", err)
	}
	configuration.Reset()
	return nil
}

func makeDescriptor(config Config, state peerState, listeners []*carrierListener) Descriptor {
	endpoints := make([]profile.Endpoint, 0, len(listeners))
	for _, listener := range listeners {
		endpoints = append(endpoints, listener.endpoint)
	}
	return Descriptor{
		SchemaVersion:     descriptorVersion,
		RunID:             config.RunID,
		PeerPublicKey:     base64.StdEncoding.EncodeToString(state.publicKey),
		ClientPublicKey:   base64.StdEncoding.EncodeToString(state.clientKey),
		Endpoints:         endpoints,
		EchoAddresses:     []string{net.JoinHostPort(peerIPv4.String(), fmt.Sprint(EchoPort)), net.JoinHostPort(peerIPv6.String(), fmt.Sprint(EchoPort))},
		CertificateSHA256: state.certHash,
		CertificatePath:   filepath.Join(config.PrivateDir, state.manifest.CertificateFile),
		ExpiresAt:         state.manifest.ExpiresAt,
	}
}

func marshalDescriptor(descriptor Descriptor) ([]byte, error) {
	if err := validateDescriptor(descriptor); err != nil {
		return nil, err
	}
	data, err := json.Marshal(descriptor)
	if err != nil || len(data) > maxDescriptorSize {
		return nil, ErrInvalidDescriptor
	}
	return append(data, '\n'), nil
}

func validateDescriptor(descriptor Descriptor) error {
	now := time.Now().Unix()
	if descriptor.SchemaVersion != descriptorVersion || !validRunID(descriptor.RunID) || !validBase64Key(descriptor.PeerPublicKey) || !validBase64Key(descriptor.ClientPublicKey) || !validHexHash(descriptor.CertificateSHA256) || !filepath.IsAbs(descriptor.CertificatePath) || descriptor.ExpiresAt <= now || descriptor.ExpiresAt > now+int64(defaultLifetime/time.Second) || len(descriptor.Endpoints) != 3 || len(descriptor.EchoAddresses) != 2 {
		return ErrInvalidDescriptor
	}
	expectedTransports := [...]profile.Transport{profile.QUIC, profile.WSS, profile.TCP}
	seenPorts := make(map[int]struct{}, len(descriptor.Endpoints))
	for index, endpoint := range descriptor.Endpoints {
		if endpoint.Transport != expectedTransports[index] {
			return ErrInvalidDescriptor
		}
		parsed, err := url.Parse(endpoint.URL)
		if err != nil || parsed.Scheme == "" || parsed.Hostname() != loopbackHost.String() || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return ErrInvalidDescriptor
		}
		expected := map[profile.Transport]string{profile.QUIC: "https", profile.WSS: "wss", profile.TCP: "tcp"}[endpoint.Transport]
		if parsed.Scheme != expected || parsed.Port() == "" || parsed.Path != "" && parsed.Path != "/" && !(endpoint.Transport == profile.WSS && parsed.Path == websocketPath) {
			return ErrInvalidDescriptor
		}
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < minCarrierPort || port >= maxCarrierPort {
			return ErrInvalidDescriptor
		}
		if _, exists := seenPorts[port]; exists {
			return ErrInvalidDescriptor
		}
		seenPorts[port] = struct{}{}
	}
	if descriptor.EchoAddresses[0] != net.JoinHostPort(peerIPv4.String(), fmt.Sprint(EchoPort)) || descriptor.EchoAddresses[1] != net.JoinHostPort(peerIPv6.String(), fmt.Sprint(EchoPort)) {
		return ErrInvalidDescriptor
	}
	return nil
}

func publishDescriptor(path string, data []byte) (os.FileInfo, error) {
	if err := rejectExistingDescriptor(path); err != nil {
		return nil, err
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := ensureOwnedDirectory(filepath.Dir(parent)); err != nil {
			return nil, err
		}
		if err := os.Mkdir(parent, 0o700); err != nil {
			return nil, err
		}
		info, err = os.Lstat(parent)
		if err != nil {
			return nil, err
		}
	}
	if !safeOwnedDirectoryInfo(info) {
		return nil, ErrUnsafeFile
	}
	temporary, err := os.CreateTemp(parent, ".descriptor-*")
	if err != nil {
		return nil, err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	temporaryInfo, err := temporary.Stat()
	if err != nil || !safeOwnedRegularInfo(temporaryInfo, 0o644) {
		_ = temporary.Close()
		return nil, ErrUnsafeFile
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	// A hard-link publication is atomic and refuses to overwrite a descriptor
	// created by another process between the preflight and publication.
	if err := os.Link(temporaryName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrExistingDescriptor
		}
		return nil, err
	}
	published, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsafeFile
	}
	defer published.Close()
	publishedInfo, err := published.Stat()
	if err != nil || !os.SameFile(temporaryInfo, publishedInfo) || !safeOwnedRegularInfo(publishedInfo, 0o644) {
		return nil, ErrUnsafeFile
	}
	return publishedInfo, nil
}

func readManifest(path string) (Manifest, error) {
	data, err := readPrivateFile(path, 0)
	if err != nil || len(data) > maxManifestSize {
		clear(data)
		return Manifest{}, errOrInvalid(err)
	}
	defer clear(data)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, ErrInvalidConfig
	}
	if decoder.Decode(&struct{}{}) != io.EOF || manifest.SchemaVersion != manifestVersion || !validRunID(manifest.RunID) || !validPorts(manifest.Ports) {
		return Manifest{}, ErrInvalidConfig
	}
	return manifest, nil
}

func writeManifest(path string, manifest Manifest) error {
	data, err := json.Marshal(manifest)
	if err != nil || len(data) > maxManifestSize {
		return ErrInvalidConfig
	}
	data = append(data, '\n')
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return ErrUnsafeFile
		}
		return ErrExistingRun
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writePrivateFile(path, data, 0o600)
}

func ensurePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := ensureOwnedDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !safeOwnedDirectoryInfo(info) {
		return ErrUnsafeFile
	}
	return nil
}

func writePrivateFile(path string, data []byte, mode os.FileMode) error {
	if err := ensureOwnedDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	openedInfo, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || closeErr != nil || !safeOwnedRegularInfo(openedInfo, mode.Perm()) || openedInfo.Size() != int64(len(data)) {
		return ErrUnsafeFile
	}
	pathInfo, statErr := os.Lstat(path)
	if statErr != nil || !os.SameFile(openedInfo, pathInfo) || !safeOwnedRegularInfo(pathInfo, mode.Perm()) || linkCount(pathInfo) != 1 {
		return ErrUnsafeFile
	}
	return nil
}

func readPrivateFile(path string, expectedSize int) ([]byte, error) {
	if err := ensureOwnedDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !safeOwnedRegularInfo(info, 0o600) || linkCount(info) != 1 {
		return nil, ErrUnsafeFile
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsafeFile
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return nil, ErrUnsafeFile
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDescriptorSize+1))
	if err != nil || expectedSize > 0 && len(data) != expectedSize || expectedSize == 0 && len(data) > maxDescriptorSize {
		clear(data)
		return nil, ErrInvalidConfig
	}
	afterInfo, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(openedInfo, afterInfo) || !os.SameFile(openedInfo, pathInfo) || openedInfo.Size() != afterInfo.Size() || int64(len(data)) != afterInfo.Size() {
		clear(data)
		return nil, ErrUnsafeFile
	}
	return data, nil
}

func validatePrivatePath(path string, expectedSize int, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || !safeOwnedRegularInfo(info, mode.Perm()) || linkCount(info) != 1 {
		return ErrUnsafeFile
	}
	if expectedSize > 0 && info.Size() != int64(expectedSize) {
		return ErrInvalidConfig
	}
	return nil
}

func errOrInvalid(err error) error {
	if err != nil {
		return err
	}
	return ErrInvalidConfig
}

func safeOwnedRegularInfo(info os.FileInfo, mode os.FileMode) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() && info.Mode().Perm() == mode.Perm() && ownedByCurrentUser(info)
}

func safeOwnedDirectoryInfo(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir() && info.Mode().Perm() == 0o700 && ownedByCurrentUser(info)
}

func ensureOwnedDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !safeOwnedDirectoryInfo(info) {
		return ErrUnsafeFile
	}
	return nil
}

func readRawPublicKey(path string) ([]byte, error) {
	data, err := readPrivateFile(path, 32)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func linkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 1
}

func ownedByCurrentUser(info os.FileInfo) bool {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Uid) == uint64(os.Getuid())
	}
	return true
}

func validPorts(ports Ports) bool {
	values := []uint16{ports.QUIC, ports.WSS, ports.TCP}
	for index, value := range values {
		if value < minCarrierPort || value >= maxCarrierPort {
			return false
		}
		for _, other := range values[:index] {
			if value == other {
				return false
			}
		}
	}
	return true
}

func choosePorts() (Ports, error) {
	for attempt := 0; attempt < 64; attempt++ {
		var bytes [6]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			return Ports{}, err
		}
		candidate := Ports{
			QUIC: minCarrierPort + uint16((uint32(bytes[0])<<8|uint32(bytes[1]))%uint32(maxCarrierPort-minCarrierPort)),
			WSS:  minCarrierPort + uint16((uint32(bytes[2])<<8|uint32(bytes[3]))%uint32(maxCarrierPort-minCarrierPort)),
			TCP:  minCarrierPort + uint16((uint32(bytes[4])<<8|uint32(bytes[5]))%uint32(maxCarrierPort-minCarrierPort)),
		}
		if validPorts(candidate) && portsAvailable(candidate) {
			return candidate, nil
		}
	}
	return Ports{}, ErrPortUnavailable
}

func portsAvailable(ports Ports) bool {
	tcp, err := net.Listen("tcp", net.JoinHostPort(loopbackHost.String(), fmt.Sprint(ports.TCP)))
	if err != nil {
		return false
	}
	_ = tcp.Close()
	tls, err := net.Listen("tcp", net.JoinHostPort(loopbackHost.String(), fmt.Sprint(ports.WSS)))
	if err != nil {
		return false
	}
	_ = tls.Close()
	udp, err := net.ListenPacket("udp", net.JoinHostPort(loopbackHost.String(), fmt.Sprint(ports.QUIC)))
	if err != nil {
		return false
	}
	_ = udp.Close()
	return true
}

func openCarrierListeners(ctx context.Context, ports Ports, certificate tls.Certificate) ([]*carrierListener, *wssRegistry, error) {
	if !validPorts(ports) {
		return nil, nil, ErrInvalidConfig
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	quicTLS := tlsConfig.Clone()
	quicTLS.NextProtos = []string{quicALPN}
	quicListener, err := quicgo.ListenAddr(net.JoinHostPort(loopbackHost.String(), fmt.Sprint(ports.QUIC)), quicTLS, &quicgo.Config{EnableDatagrams: true})
	if err != nil {
		return nil, nil, fmt.Errorf("listen loopback QUIC: %w", err)
	}
	listeners := []*carrierListener{{
		transport: profile.QUIC,
		endpoint:  profile.Endpoint{Transport: profile.QUIC, URL: "https://" + net.JoinHostPort(loopbackHost.String(), fmt.Sprint(ports.QUIC))},
		accept: func(ctx context.Context) (carrier.Carrier, error) {
			connection, err := quicListener.Accept(ctx)
			if err != nil {
				return nil, err
			}
			return carrier.AcceptQUIC(connection)
		},
		close: quicListener.Close,
	}}
	wsTCP, err := tls.Listen("tcp", net.JoinHostPort(loopbackHost.String(), fmt.Sprint(ports.WSS)), tlsConfig)
	if err != nil {
		_ = quicListener.Close()
		return nil, nil, fmt.Errorf("listen loopback WSS: %w", err)
	}
	wssConnections := newWSSRegistry()
	wsAccepted := make(chan carrier.Carrier, 4)
	wsErrors := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(websocketPath, func(response http.ResponseWriter, request *http.Request) {
		if !wssConnections.beginHandler() {
			return
		}
		defer wssConnections.endHandler()
		connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			select {
			case wsErrors <- err:
			default:
			}
			return
		}
		stream := carrier.NewStream(websocket.NetConn(context.Background(), connection, websocket.MessageBinary))
		registered, err := wssConnections.register(stream, connection.CloseNow)
		if err != nil {
			_ = stream.Close()
			return
		}
		select {
		case wsAccepted <- registered:
		case <-request.Context().Done():
			_ = registered.Close()
		case <-wssConnections.stopping():
			_ = registered.Close()
		}
	})
	wsServer := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	wsServerDone := make(chan struct{})
	go func() {
		defer close(wsServerDone)
		_ = wsServer.Serve(wsTCP)
	}()
	var closeWSSOnce sync.Once
	listeners = append(listeners, &carrierListener{
		transport: profile.WSS,
		endpoint:  profile.Endpoint{Transport: profile.WSS, URL: "wss://" + net.JoinHostPort(loopbackHost.String(), fmt.Sprint(ports.WSS)) + websocketPath},
		accept: func(ctx context.Context) (carrier.Carrier, error) {
			select {
			case value := <-wsAccepted:
				return value, nil
			case err := <-wsErrors:
				return nil, err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		close: func() error {
			var closeErr error
			closeWSSOnce.Do(func() {
				closeErr = wsServer.Close()
				if err := wsTCP.Close(); closeErr == nil && !errors.Is(err, net.ErrClosed) {
					closeErr = err
				}
				wssConnections.closeAndWait()
				<-wsServerDone
			})
			return closeErr
		},
	})
	tcpListener, err := tls.Listen("tcp", net.JoinHostPort(loopbackHost.String(), fmt.Sprint(ports.TCP)), tlsConfig)
	if err != nil {
		closeCarrierListeners(listeners)
		return nil, nil, fmt.Errorf("listen loopback TCP: %w", err)
	}
	listeners = append(listeners, &carrierListener{
		transport: profile.TCP,
		endpoint:  profile.Endpoint{Transport: profile.TCP, URL: "tcp://" + net.JoinHostPort(loopbackHost.String(), fmt.Sprint(ports.TCP))},
		accept: func(ctx context.Context) (carrier.Carrier, error) {
			connection, err := acceptContext(ctx, tcpListener)
			if err != nil {
				return nil, err
			}
			tlsConnection := connection.(*tls.Conn)
			handshakeContext, cancel := context.WithTimeout(ctx, tlsHandshakeLimit)
			defer cancel()
			if err := tlsConnection.HandshakeContext(handshakeContext); err != nil {
				_ = tlsConnection.Close()
				return nil, err
			}
			return carrier.NewStream(tlsConnection), nil
		},
		close: tcpListener.Close,
	})
	return listeners, wssConnections, nil
}

func openEchoListeners(network *netstack.Net) ([]net.Listener, error) {
	if network == nil {
		return nil, ErrInvalidConfig
	}
	port := netip.AddrPortFrom(peerIPv4, EchoPort)
	ipv4, err := network.ListenTCPAddrPort(port)
	if err != nil {
		return nil, fmt.Errorf("listen IPv4 private echo: %w", err)
	}
	ipv6, err := network.ListenTCPAddrPort(netip.AddrPortFrom(peerIPv6, EchoPort))
	if err != nil {
		_ = ipv4.Close()
		return nil, fmt.Errorf("listen IPv6 private echo: %w", err)
	}
	return []net.Listener{ipv4, ipv6}, nil
}

func closeCarrierListeners(listeners []*carrierListener) {
	for _, listener := range listeners {
		if listener != nil && listener.close != nil {
			_ = listener.close()
		}
	}
}

func closeNetListeners(listeners []net.Listener) {
	for _, listener := range listeners {
		if listener != nil {
			_ = listener.Close()
		}
	}
}

func acceptContext(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type result struct {
		connection net.Conn
		err        error
	}
	results := make(chan result, 1)
	go func() {
		connection, err := listener.Accept()
		results <- result{connection: connection, err: err}
	}()
	select {
	case value := <-results:
		return value.connection, value.err
	case <-ctx.Done():
		_ = listener.Close()
		return nil, ctx.Err()
	}
}

func closeState(state peerState) {
	clear(state.privateKey)
	clear(state.clientKey)
	releaseSensitiveKey(&state.tlsKey)
}

func sum256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func hashHex(data []byte) string { return hex.EncodeToString(sum256(data)) }

func validHexHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validBase64Key(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	valid := err == nil && len(decoded) == 32
	clear(decoded)
	return valid
}

func bytesEqualBase64(value []byte, encoded string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != len(value) {
		clear(decoded)
		return false
	}
	equal := true
	for index := range value {
		equal = equal && value[index] == decoded[index]
	}
	clear(decoded)
	return equal
}
