// kyclash-system-trust-probe is a guest-only verification helper.  It uses
// the exact carrier.DialTCP path used by the production sidecar while leaving
// RootCAs nil, which delegates certificate verification to the macOS platform
// trust store.  The helper is never bundled into KyClash and must be built
// with CGO_ENABLED=0 before it is copied into the disposable VM.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/carrier"
)

const (
	probePayload       = "kyclash-system-trust-v1"
	maxCertificateSize = 128 * 1024
	maxPrivateKeySize  = 128 * 1024
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func main() {
	if err := requireGuestRuntime(); err != nil {
		fmt.Fprintln(os.Stderr, "KyClash system trust probe refused")
		os.Exit(1)
	}
	if err := run(os.Args[1:]); err != nil {
		// Keep the process boundary deliberately fixed-status.  In particular,
		// do not expose certificate, key, endpoint, or system trust diagnostics.
		fmt.Fprintln(os.Stderr, "KyClash system trust probe failed")
		os.Exit(1)
	}
	fmt.Println("kyclash_system_trust_probe=passed")
	fmt.Println("cgo_enabled=0")
}

func requireGuestRuntime() error {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return errors.New("system trust probe requires arm64 macOS")
	}
	if os.Getenv("KYCLASH_RUNNER_ENVIRONMENT") != "local-virtualization-framework" ||
		os.Getenv("KYCLASH_VM_LAB_CONFIRM") != "authorized-kyclash-virtualization-framework-vm" ||
		os.Getenv("KYCLASH_RUNTIME_TARGET") != "kyclash-macos-lab-work" {
		return errors.New("system trust probe requires the authorized VM markers")
	}
	model, err := exec.Command("/usr/sbin/sysctl", "-n", "hw.model").Output()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(model)), "VirtualMac") {
		return errors.New("system trust probe requires a VirtualMac guest")
	}
	return nil
}

func run(arguments []string) error {
	if runtimeGOOS() != "darwin" || !builtWithCGODisabled {
		return errors.New("guest probe requires a darwin CGO-disabled build")
	}
	if len(arguments) != 6 || arguments[0] != "--root-cert" || arguments[2] != "--leaf-cert" || arguments[4] != "--leaf-key" {
		return errors.New("invalid arguments")
	}
	rootPEM, err := readRegular(arguments[1], maxCertificateSize, false)
	if err != nil {
		return err
	}
	leafPEM, err := readRegular(arguments[3], maxCertificateSize, false)
	if err != nil {
		return err
	}
	keyPEM, err := readRegular(arguments[5], maxPrivateKeySize, true)
	if err != nil {
		return err
	}
	defer clear(keyPEM)
	root, err := parseCertificate(rootPEM)
	if err != nil {
		return err
	}
	leaf, err := parseCertificate(leafPEM)
	if err != nil {
		return err
	}
	rootDigest := sha256.Sum256(root.Raw)
	leafDigest := sha256.Sum256(leaf.Raw)
	wantedRoot := strings.TrimSpace(os.Getenv("KYCLASH_SYSTEM_TRUST_ROOT_SHA256"))
	wantedLeaf := strings.TrimSpace(os.Getenv("KYCLASH_SYSTEM_TRUST_LEAF_SHA256"))
	if !digestPattern.MatchString(wantedRoot) || hex.EncodeToString(rootDigest[:]) != wantedRoot ||
		!digestPattern.MatchString(wantedLeaf) || hex.EncodeToString(leafDigest[:]) != wantedLeaf {
		return errors.New("certificate fingerprint mismatch")
	}
	now := time.Now()
	if !root.IsCA ||
		!root.BasicConstraintsValid ||
		root.Subject.String() != root.Issuer.String() ||
		root.CheckSignatureFrom(root) != nil ||
		now.Before(root.NotBefore) ||
		now.After(root.NotAfter) {
		return errors.New("invalid trust root")
	}
	if leaf.IsCA ||
		!leaf.BasicConstraintsValid ||
		len(leaf.DNSNames) != 0 ||
		len(leaf.IPAddresses) != 1 ||
		!leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) ||
		now.Before(leaf.NotBefore) ||
		now.After(leaf.NotAfter) ||
		leaf.NotAfter.After(root.NotAfter) {
		return errors.New("leaf is not a current numeric loopback certificate")
	}
	serverAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		return errors.New("leaf lacks server authentication usage")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: func() *x509.CertPool { pool := x509.NewCertPool(); pool.AddCert(root); return pool }(), DNSName: "127.0.0.1"}); err != nil {
		return errors.New("leaf does not chain to trust root")
	}
	pair, err := tls.X509KeyPair(append(append([]byte(nil), leafPEM...), rootPEM...), keyPEM)
	if err != nil {
		return errors.New("certificate and key do not match")
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go serveEcho(listener, serverResult)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := carrier.DialTCP(ctx, carrier.TCPConfig{
		Address:    listener.Addr().String(),
		ServerName: "127.0.0.1",
		// This nil is intentional: it is the production sidecar's platform
		// trust boundary.  The fixture must not add a lab RootCAs API.
		RootCAs: nil,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Send(ctx, []byte(probePayload)); err != nil {
		return err
	}
	response, err := client.Receive(ctx)
	if err != nil {
		return err
	}
	if string(response) != probePayload {
		return errors.New("unexpected trust probe response")
	}
	select {
	case err := <-serverResult:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid certificate input")
	}
	return x509.ParseCertificate(block.Bytes)
}

func serveEcho(listener net.Listener, result chan<- error) {
	connection, err := listener.Accept()
	if err != nil {
		result <- err
		return
	}
	stream := carrier.NewStream(connection)
	defer stream.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	payload, err := stream.Receive(ctx)
	if err == nil && string(payload) != probePayload {
		err = errors.New("unexpected trust probe request")
	}
	if err == nil {
		err = stream.Send(ctx, payload)
	}
	result <- err
}

func readRegular(path string, limit int64, private bool) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("fixture paths must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("fixture path is not a bounded regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > limit || stat.Nlink != 1 || uint32(os.Getuid()) != stat.Uid {
		return nil, errors.New("fixture path is not a bounded regular file")
	}
	mode := info.Mode().Perm()
	if private {
		if mode != 0o600 {
			return nil, errors.New("private fixture mode must be 0600")
		}
	} else if mode != 0o600 && mode != 0o644 {
		return nil, errors.New("certificate fixture mode must be 0600 or 0644")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("fixture path changed while it was being opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	// The path and descriptor were checked before the read, but a same-inode
	// truncate/extend must not be accepted as trusted fixture input. Re-stat
	// the descriptor and require the exact size/link/owner shape to remain
	// stable for the complete read.
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || after.Size() != info.Size() || after.Mode().Perm() != info.Mode().Perm() {
		clear(data)
		return nil, errors.New("fixture path changed while it was being read")
	}
	if int64(len(data)) != after.Size() || int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("fixture input exceeds its size limit")
	}
	return data, nil
}

// Kept in a tiny function so the build remains easy to audit without pulling
// platform-specific packages into the command's public contract.
func runtimeGOOS() string {
	return runtime.GOOS
}
