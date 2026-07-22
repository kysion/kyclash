// kyclash-networking-system-lab is the disposable-VM guest peer for the
// networking-production candidate review.  It is a standalone lab fixture;
// it is never bundled into KyClash or used as the production sidecar.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kysion/kyclash/network-sidecar/internal/systemlabpeer"
)

const parentWatchInterval = 100 * time.Millisecond

const (
	runnerEnvironment = "local-virtualization-framework"
	vmConfirmation    = "authorized-kyclash-virtualization-framework-vm"
	runtimeTarget     = "kyclash-macos-lab-work"
)

type arguments struct {
	runID               string
	clientPublicKeyPath string
	privateDir          string
	descriptorPath      string
	manifestPath        string
	rootCertificatePath string
	certificatePath     string
	tlsPrivateKeyPath   string
	expiresAt           int64
	hasExpiresAt        bool
}

func parseArguments(values []string) (arguments, error) {
	flags := flag.NewFlagSet("kyclash-networking-system-lab", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var parsed arguments
	flags.StringVar(&parsed.runID, "run-id", "", "16 lowercase hexadecimal run identifier")
	flags.StringVar(&parsed.clientPublicKeyPath, "client-public-key", "", "0600 file containing the 32-byte client public key")
	flags.StringVar(&parsed.privateDir, "private-dir", "", "0700 guest-only private run directory")
	flags.StringVar(&parsed.descriptorPath, "descriptor", "", "public descriptor output path")
	flags.StringVar(&parsed.manifestPath, "manifest", "", "private manifest path (defaults to private-dir/manifest.json)")
	flags.StringVar(&parsed.rootCertificatePath, "root-cert", "", "guest-only PEM root certificate from the trust fixture")
	flags.StringVar(&parsed.certificatePath, "leaf-cert", "", "guest-only PEM loopback leaf certificate from the trust fixture")
	flags.StringVar(&parsed.tlsPrivateKeyPath, "leaf-key", "", "guest-only 0600 PEM/raw loopback leaf key")
	var expiresAtText string
	flags.StringVar(&expiresAtText, "expires-at", "", "run-bound descriptor expiry epoch")
	if err := flags.Parse(values); err != nil || flags.NArg() != 0 {
		return arguments{}, errors.New("invalid arguments")
	}
	if parsed.runID == "" || parsed.clientPublicKeyPath == "" || parsed.privateDir == "" || parsed.descriptorPath == "" {
		return arguments{}, errors.New("required arguments are missing")
	}
	if expiresAtText != "" {
		value, err := strconv.ParseInt(expiresAtText, 10, 64)
		if err != nil || value <= 0 {
			return arguments{}, errors.New("invalid expiry")
		}
		parsed.expiresAt, parsed.hasExpiresAt = value, true
	}
	if (parsed.rootCertificatePath != "" || parsed.certificatePath != "" || parsed.tlsPrivateKeyPath != "") && !parsed.hasExpiresAt {
		return arguments{}, errors.New("fixture expiry is required")
	}
	return parsed, nil
}

func run(values []string, stdin io.Reader, stdout io.Writer) error {
	parsed, err := parseArguments(values)
	if err != nil {
		return err
	}
	parentID := os.Getppid()
	if err := requireLiveParent(parentID); err != nil {
		return err
	}
	parentContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithCancel(parentContext)
	defer cancel()
	go watchParent(ctx, parentID, cancel)
	go cancelOnEOF(ctx, stdin, cancel)

	peerConfig := systemlabpeer.Config{
		RunID:               parsed.runID,
		ClientPublicKeyPath: parsed.clientPublicKeyPath,
		PrivateDir:          parsed.privateDir,
		DescriptorPath:      parsed.descriptorPath,
		ManifestPath:        parsed.manifestPath,
		RootCertificatePath: parsed.rootCertificatePath,
		CertificatePath:     parsed.certificatePath,
		TLSPrivateKeyPath:   parsed.tlsPrivateKeyPath,
	}
	if parsed.hasExpiresAt {
		peerConfig.ExpiresAt = time.Unix(parsed.expiresAt, 0).UTC()
	}
	peer, err := systemlabpeer.Start(ctx, peerConfig)
	if err != nil {
		return errors.New("system lab peer preparation failed")
	}
	defer peer.Close()
	if err := peer.WaitReady(ctx); err != nil {
		return errors.New("system lab peer did not become ready")
	}
	// The controller already knows the descriptor path.  Keep stdout fixed and
	// redacted: no endpoint, certificate, key, or policy bytes are printed.
	if _, err := io.WriteString(stdout, "KYCLASH_SYSTEM_LAB_READY\n"); err != nil {
		return err
	}
	select {
	case err := <-peer.Done():
		return err
	case <-ctx.Done():
		_ = peer.Close()
		<-peer.Done()
		return nil
	}
}

func requireLiveParent(parentID int) error {
	if parentID <= 1 {
		return systemlabpeer.ErrParentClosed
	}
	return nil
}

func cancelOnEOF(ctx context.Context, reader io.Reader, cancel context.CancelFunc) {
	if reader == nil {
		cancel()
		return
	}
	_, _ = io.Copy(io.Discard, reader)
	if ctx.Err() == nil {
		cancel()
	}
}

func watchParent(ctx context.Context, initialParent int, cancel context.CancelFunc) {
	if initialParent <= 1 {
		// A child that starts already re-parented has no trustworthy controller
		// identity. Fail closed immediately even when inherited stdin remains
		// open; otherwise the peer could publish a descriptor with no owner.
		cancel()
		return
	}
	ticker := time.NewTicker(parentWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if os.Getppid() != initialParent {
				cancel()
				return
			}
		}
	}
}

func execute(values []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if err := requireGuestRuntime(); err != nil {
		_, _ = fmt.Fprintln(stderr, "KyClash system lab peer refused")
		return 1
	}
	if err := run(values, stdin, stdout); err != nil {
		// Keep the public process output fixed.  Detailed errors stay with the
		// caller's local test harness and are never emitted with secret paths.
		_, _ = fmt.Fprintln(stderr, "KyClash system lab peer failed")
		return 1
	}
	return 0
}

// requireGuestRuntime is intentionally placed at the process boundary. Unit
// tests can exercise the userspace peer on Linux, while a real invocation can
// never accidentally become a host or physical-Mac networking process.
func requireGuestRuntime() error {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return errors.New("system lab peer requires arm64 macOS")
	}
	if os.Getenv("KYCLASH_RUNNER_ENVIRONMENT") != runnerEnvironment ||
		os.Getenv("KYCLASH_VM_LAB_CONFIRM") != vmConfirmation ||
		os.Getenv("KYCLASH_RUNTIME_TARGET") != runtimeTarget {
		return errors.New("system lab peer requires the authorized VM markers")
	}
	model, err := exec.Command("/usr/sbin/sysctl", "-n", "hw.model").Output()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(model)), "VirtualMac") {
		return errors.New("system lab peer requires a VirtualMac guest")
	}
	return nil
}

func main() { os.Exit(execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
