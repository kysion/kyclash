package labserver

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"io"
	"net"
	"sync"

	"github.com/kysion/kyclash/network-sidecar/internal/profile"
	"golang.org/x/crypto/curve25519"
)

const ProbeAddress = "10.88.0.2:8080"

type Cluster struct {
	servers map[profile.Transport]*Server
	roots   *x509.CertPool
	peerKey string
	once    sync.Once
}

func StartCluster(ctx context.Context, clientPublicKey []byte) (*Cluster, error) {
	if len(clientPublicKey) != curve25519.PointSize {
		return nil, ErrInvalid
	}
	serverPrivate := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(serverPrivate); err != nil {
		return nil, err
	}
	defer clear(serverPrivate)
	cluster := &Cluster{servers: make(map[profile.Transport]*Server), roots: x509.NewCertPool()}
	for _, transport := range []profile.Transport{profile.QUIC, profile.WSS, profile.TCP} {
		server, err := Start(ctx, Config{Transport: transport, ClientPublicKey: clientPublicKey, ServerPrivateKey: serverPrivate, AutoEcho: true})
		if err != nil {
			_ = cluster.Close()
			return nil, err
		}
		cluster.servers[transport] = server
		certificate, err := x509.ParseCertificate(server.CertificateDER())
		if err != nil {
			_ = cluster.Close()
			return nil, err
		}
		cluster.roots.AddCert(certificate)
		if cluster.peerKey == "" {
			cluster.peerKey = server.PeerPublicKey()
		}
	}
	return cluster, nil
}

func (cluster *Cluster) Endpoints() []profile.Endpoint {
	return []profile.Endpoint{cluster.servers[profile.QUIC].Endpoint(), cluster.servers[profile.WSS].Endpoint(), cluster.servers[profile.TCP].Endpoint()}
}
func (cluster *Cluster) Roots() *x509.CertPool { return cluster.roots.Clone() }
func (cluster *Cluster) PeerPublicKey() string { return cluster.peerKey }
func (cluster *Cluster) WaitReady(ctx context.Context, transport profile.Transport) error {
	server := cluster.servers[transport]
	if server == nil {
		return ErrInvalid
	}
	return server.WaitReady(ctx)
}
func (cluster *Cluster) Done(transport profile.Transport) <-chan error {
	server := cluster.servers[transport]
	if server == nil {
		closed := make(chan error)
		close(closed)
		return closed
	}
	return server.Done()
}
func (cluster *Cluster) Close() error {
	cluster.once.Do(func() {
		for _, server := range cluster.servers {
			_ = server.Close()
		}
	})
	return nil
}

func echoLoop(ctx context.Context, listener net.Listener) {
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func(connection net.Conn) { defer connection.Close(); _, _ = io.Copy(connection, connection) }(connection)
	}
}
