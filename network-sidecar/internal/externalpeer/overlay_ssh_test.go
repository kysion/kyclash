package externalpeer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestOverlaySSHProvesPinnedNoShellNonce(t *testing.T) {
	hostPublic, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(hostPrivate)
	defer clear(clientPrivate)
	hostSSH, _ := ssh.NewPublicKey(hostPublic)
	clientSSH, _ := ssh.NewPublicKey(clientPublic)
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewOverlaySSHServer(
		listener,
		hostPrivate,
		clientSSH.Marshal(),
		nonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	proved := make(chan struct{}, 1)
	server.SetProofCallback(func() {
		proved <- struct{}{}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp4", listener.Addr().String())
	}
	probeContext, probeCancel := context.WithTimeout(ctx, 5*time.Second)
	defer probeCancel()
	if err := ProbeOverlaySSH(
		probeContext,
		"10.88.0.2:22",
		clientPrivate,
		hostSSH.Marshal(),
		HashHex(nonce),
		dial,
	); err != nil {
		t.Fatal(err)
	}
	select {
	case <-proved:
	case <-time.After(time.Second):
		t.Fatal("server did not record the client-confirmed SSH proof")
	}
	wrongPublic, wrongPrivate, _ := ed25519.GenerateKey(rand.Reader)
	clear(wrongPublic)
	defer clear(wrongPrivate)
	if err := ProbeOverlaySSH(
		probeContext,
		"10.88.0.2:22",
		wrongPrivate,
		hostSSH.Marshal(),
		HashHex(nonce),
		dial,
	); err == nil {
		t.Fatal("wrong client key was accepted")
	}
	cancel()
	_ = server.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SSH server did not stop")
	}
}

func TestOverlaySSHRejectsArbitraryExecAndPTY(t *testing.T) {
	hostPublic, hostPrivate, _ := ed25519.GenerateKey(rand.Reader)
	clientPublic, clientPrivate, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(hostPrivate)
	defer clear(clientPrivate)
	hostSSH, _ := ssh.NewPublicKey(hostPublic)
	clientSSH, _ := ssh.NewPublicKey(clientPublic)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	server, err := NewOverlaySSHServer(listener, hostPrivate, clientSSH.Marshal(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)
	raw, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(clientPrivate)
	connection, channels, requests, err := ssh.NewClientConn(raw, listener.Addr().String(), &ssh.ClientConfig{
		User: "kyclashlabssh",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if string(key.Marshal()) != string(hostSSH.Marshal()) {
				return ErrSSHProof
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(connection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Fatal("PTY request was accepted")
	}
	_ = session.Close()
	session, err = client.NewSession()
	if err == nil {
		if err := session.Run("uname -a"); err == nil {
			t.Fatal("arbitrary command was accepted")
		}
		_ = session.Close()
	}
}

func TestOverlaySSHRejectsEarlyMissingAndWrongProofACK(t *testing.T) {
	hostPublic, hostPrivate, _ := ed25519.GenerateKey(rand.Reader)
	clientPublic, clientPrivate, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(hostPrivate)
	defer clear(clientPrivate)
	hostSSH, _ := ssh.NewPublicKey(hostPublic)
	clientSSH, _ := ssh.NewPublicKey(clientPublic)
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewOverlaySSHServer(
		listener,
		hostPrivate,
		clientSSH.Marshal(),
		nonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	proved := make(chan struct{}, 1)
	server.SetProofCallback(func() { proved <- struct{}{} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)
	openClient := func() *ssh.Client {
		t.Helper()
		raw, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		signer, _ := ssh.NewSignerFromKey(clientPrivate)
		connection, channels, requests, err := ssh.NewClientConn(
			raw,
			listener.Addr().String(),
			&ssh.ClientConfig{
				User: "kyclashlabssh",
				Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
				HostKeyCallback: func(
					_ string,
					_ net.Addr,
					key ssh.PublicKey,
				) error {
					if string(key.Marshal()) != string(hostSSH.Marshal()) {
						return ErrSSHProof
					}
					return nil
				},
			},
		)
		if err != nil {
			_ = raw.Close()
			t.Fatal(err)
		}
		return ssh.NewClient(connection, channels, requests)
	}
	assertNoProof := func(label string) {
		t.Helper()
		select {
		case <-proved:
			t.Fatalf("%s triggered a proof callback", label)
		case <-time.After(50 * time.Millisecond):
		}
	}

	client := openClient()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	ack := overlaySSHProofACK(nonce)
	ok, sendErr := session.SendRequest(OverlaySSHProofACKName, true, ack[:])
	clear(ack[:])
	if sendErr == nil && ok {
		t.Fatal("proof ACK before fixed exec was accepted")
	}
	_ = session.Close()
	_ = client.Close()
	assertNoProof("early ACK")

	client = openClient()
	session, err = client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start(ForcedCommandName); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, 32)
	if _, err := io.ReadFull(stdout, received); err != nil {
		t.Fatal(err)
	}
	ack = overlaySSHProofACK(received)
	clear(received)
	ack[0] ^= 0xff
	ok, sendErr = session.SendRequest(OverlaySSHProofACKName, true, ack[:])
	clear(ack[:])
	if sendErr == nil && ok {
		t.Fatal("wrong proof ACK was accepted")
	}
	_ = session.Close()
	_ = client.Close()
	assertNoProof("wrong ACK")

	client = openClient()
	session, err = client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err = session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start(ForcedCommandName); err != nil {
		t.Fatal(err)
	}
	received = make([]byte, 32)
	if _, err := io.ReadFull(stdout, received); err != nil {
		t.Fatal(err)
	}
	clear(received)
	_ = session.Close()
	_ = client.Close()
	assertNoProof("missing ACK")
	_ = server.Close()
}

func TestFixedSystemSSHProxyCannotSelectTarget(t *testing.T) {
	overlay, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- serveFixedSystemSSHProxy(
			ctx,
			overlay,
			func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp4" || address != "127.0.0.1:22" {
					t.Errorf("unexpected proxy target %s %s", network, address)
				}
				var dialer net.Dialer
				return dialer.DialContext(ctx, "tcp4", target.Addr().String())
			},
		)
	}()
	targetDone := make(chan error, 1)
	go func() {
		connection, err := target.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		defer connection.Close()
		buffer := make([]byte, 4)
		_, err = io.ReadFull(connection, buffer)
		if err == nil && string(buffer) != "ping" {
			err = ErrSSHProof
		}
		if err == nil {
			_, err = connection.Write([]byte("pong"))
		}
		targetDone <- err
	}()
	client, err := net.Dial("tcp4", overlay.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil || string(response) != "pong" {
		t.Fatalf("proxy response %q: %v", response, err)
	}
	_ = client.Close()
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = overlay.Close()
	select {
	case err := <-proxyDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not stop")
	}
}
