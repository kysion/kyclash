package externalpeer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var ErrSSHProof = errors.New("external-peer SSH proof failed")

type OverlaySSHServer struct {
	listener  net.Listener
	config    *ssh.ServerConfig
	runNonce  []byte
	nonceMu   sync.RWMutex
	closeOnce sync.Once
	proofMu   sync.Mutex
	proof     func() func()
}

func (server *OverlaySSHServer) SetProofCallback(callback func()) {
	if server == nil {
		return
	}
	server.proofMu.Lock()
	server.proof = func() func() { return callback }
	server.proofMu.Unlock()
}

func (server *OverlaySSHServer) SetProofCallbackFactory(
	factory func() func(),
) {
	if server == nil {
		return
	}
	server.proofMu.Lock()
	server.proof = factory
	server.proofMu.Unlock()
}

func NewOverlaySSHServer(
	listener net.Listener,
	hostPrivateKey ed25519.PrivateKey,
	clientPublicArtifact []byte,
	runNonce []byte,
) (*OverlaySSHServer, error) {
	if listener == nil ||
		len(hostPrivateKey) != ed25519.PrivateKeySize ||
		len(runNonce) != 32 {
		return nil, ErrSSHProof
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		return nil, ErrSSHProof
	}
	clientKey, err := ssh.ParsePublicKey(clientPublicArtifact)
	if err != nil ||
		clientKey.Type() != ssh.KeyAlgoED25519 ||
		!bytes.Equal(clientKey.Marshal(), clientPublicArtifact) {
		return nil, ErrSSHProof
	}
	expectedClient := append([]byte(nil), clientPublicArtifact...)
	config := &ssh.ServerConfig{
		NoClientAuth: false,
		MaxAuthTries: 1,
		PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if metadata == nil ||
				metadata.User() != "kyclashlabssh" ||
				key == nil ||
				!bytes.Equal(key.Marshal(), expectedClient) {
				return nil, ErrSSHProof
			}
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(hostSigner)
	return &OverlaySSHServer{
		listener: listener,
		config:   config,
		runNonce: append([]byte(nil), runNonce...),
	}, nil
}

func (server *OverlaySSHServer) Serve(ctx context.Context) error {
	if server == nil || server.listener == nil || server.config == nil {
		return ErrSSHProof
	}
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()
	var wait sync.WaitGroup
	defer wait.Wait()
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			server.handle(connection)
		}()
	}
}

func (server *OverlaySSHServer) Close() error {
	if server == nil {
		return nil
	}
	var closeErr error
	server.closeOnce.Do(func() {
		server.nonceMu.Lock()
		clear(server.runNonce)
		server.runNonce = nil
		server.nonceMu.Unlock()
		if server.listener != nil {
			closeErr = server.listener.Close()
		}
	})
	return closeErr
}

func (server *OverlaySSHServer) handle(raw net.Conn) {
	defer raw.Close()
	server.proofMu.Lock()
	factory := server.proof
	server.proofMu.Unlock()
	var onProof func()
	if factory != nil {
		onProof = factory()
	}
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	connection, channels, globalRequests, err := ssh.NewServerConn(raw, server.config)
	if err != nil {
		return
	}
	defer connection.Close()
	go ssh.DiscardRequests(globalRequests)
	accepted := false
	proved := false
	for channelRequest := range channels {
		if accepted || channelRequest.ChannelType() != "session" {
			_ = channelRequest.Reject(ssh.Prohibited, "fixed no-shell proof only")
			continue
		}
		channel, requests, err := channelRequest.Accept()
		if err != nil {
			return
		}
		accepted = true
		proved = server.handleSession(channel, requests)
	}
	if proved && onProof != nil {
		onProof()
	}
}

func (server *OverlaySSHServer) handleSession(
	channel ssh.Channel,
	requests <-chan *ssh.Request,
) bool {
	defer channel.Close()
	server.nonceMu.RLock()
	runNonce := append([]byte(nil), server.runNonce...)
	server.nonceMu.RUnlock()
	if len(runNonce) != 32 {
		clear(runNonce)
		return false
	}
	defer clear(runNonce)
	executed := false
	for request := range requests {
		if !executed {
			if request.Type != "exec" {
				_ = request.Reply(false, nil)
				return false
			}
			var payload struct {
				Command string
			}
			if err := ssh.Unmarshal(request.Payload, &payload); err != nil ||
				payload.Command != ForcedCommandName {
				_ = request.Reply(false, nil)
				return false
			}
			if err := request.Reply(true, nil); err != nil {
				return false
			}
			executed = true
			if _, err := channel.Write(runNonce); err != nil {
				return false
			}
			continue
		}
		expectedACK := overlaySSHProofACK(runNonce)
		validACK := request.Type == OverlaySSHProofACKName &&
			request.WantReply &&
			bytes.Equal(request.Payload, expectedACK[:])
		clear(expectedACK[:])
		if !validACK {
			_ = request.Reply(false, nil)
			return false
		}
		if err := request.Reply(true, nil); err != nil {
			return false
		}
		status := struct{ Status uint32 }{Status: 0}
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&status))
		return true
	}
	return false
}

type OverlayDialContext func(context.Context, string, string) (net.Conn, error)

func ProbeOverlaySSH(
	ctx context.Context,
	address string,
	clientPrivateKey ed25519.PrivateKey,
	expectedHostPublicArtifact []byte,
	expectedRunNonceSHA256 string,
	dial OverlayDialContext,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if address != net.JoinHostPort(InnerPeerIPv4, "22") ||
		len(clientPrivateKey) != ed25519.PrivateKeySize ||
		!validSHA256(expectedRunNonceSHA256) ||
		dial == nil {
		return ErrSSHProof
	}
	hostKey, err := ssh.ParsePublicKey(expectedHostPublicArtifact)
	if err != nil ||
		hostKey.Type() != ssh.KeyAlgoED25519 ||
		!bytes.Equal(hostKey.Marshal(), expectedHostPublicArtifact) {
		return ErrSSHProof
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPrivateKey)
	if err != nil {
		return ErrSSHProof
	}
	raw, err := dial(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHProof, err)
	}
	defer raw.Close()
	deadline := time.Now().Add(10 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = raw.SetDeadline(deadline)
	config := &ssh.ClientConfig{
		User: "kyclashlabssh",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if key == nil || !bytes.Equal(key.Marshal(), expectedHostPublicArtifact) {
				return ErrSSHProof
			}
			return nil
		},
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout:           10 * time.Second,
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(raw, address, config)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHProof, err)
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHProof, err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHProof, err)
	}
	if err := session.Start(ForcedCommandName); err != nil {
		return fmt.Errorf("%w: %v", ErrSSHProof, err)
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(stdout, nonce); err != nil ||
		HashHex(nonce) != expectedRunNonceSHA256 {
		clear(nonce)
		return ErrSSHProof
	}
	ack := overlaySSHProofACK(nonce)
	clear(nonce)
	ok, err := session.SendRequest(
		OverlaySSHProofACKName,
		true,
		ack[:],
	)
	clear(ack[:])
	if err != nil || !ok {
		return ErrSSHProof
	}
	if err := session.Wait(); err != nil {
		return fmt.Errorf("%w: %v", ErrSSHProof, err)
	}
	return nil
}

func overlaySSHProofACK(nonce []byte) [sha256.Size]byte {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(OverlaySSHProofACKDomain))
	_, _ = hasher.Write(nonce)
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

// ServeFixedSystemSSHProxy exposes only the reviewed overlay listener. Every
// accepted stream is connected to numeric 127.0.0.1:22 from numeric
// 127.0.0.1. There is no target-selection or DNS surface.
func ServeFixedSystemSSHProxy(ctx context.Context, overlay net.Listener) error {
	return serveFixedSystemSSHProxy(ctx, overlay, func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := net.Dialer{
			LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
		}
		return dialer.DialContext(ctx, network, address)
	})
}

func serveFixedSystemSSHProxy(
	ctx context.Context,
	overlay net.Listener,
	dial OverlayDialContext,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if overlay == nil || dial == nil {
		return ErrSSHProof
	}
	go func() {
		<-ctx.Done()
		_ = overlay.Close()
	}()
	var wait sync.WaitGroup
	defer wait.Wait()
	for {
		inbound, err := overlay.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		outbound, err := dial(ctx, "tcp4", "127.0.0.1:22")
		if err != nil {
			_ = inbound.Close()
			continue
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			proxyPair(inbound, outbound)
		}()
	}
}

func proxyPair(left, right net.Conn) {
	defer left.Close()
	defer right.Close()
	result := make(chan struct{}, 2)
	copyOne := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		if closer, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		result <- struct{}{}
	}
	go copyOne(left, right)
	go copyOne(right, left)
	<-result
	<-result
}
