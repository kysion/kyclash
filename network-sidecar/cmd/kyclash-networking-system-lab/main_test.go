package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestParseArgumentsRequiresBoundedGuestPaths(t *testing.T) {
	if _, err := parseArguments([]string{"--run-id", "bad"}); err == nil {
		t.Fatal("incomplete arguments were accepted")
	}
	parsed, err := parseArguments([]string{
		"--run-id", "0123456789abcdef",
		"--client-public-key", "/var/tmp/client.key",
		"--private-dir", "/var/tmp/peer",
		"--descriptor", "/var/tmp/descriptor.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.runID != "0123456789abcdef" || parsed.privateDir != "/var/tmp/peer" {
		t.Fatalf("unexpected parsed arguments: %#v", parsed)
	}
	if _, err := parseArguments([]string{
		"--run-id", "0123456789abcdef",
		"--client-public-key", "/var/tmp/client.key",
		"--private-dir", "/var/tmp/peer",
		"--descriptor", "/var/tmp/descriptor.json",
		"unexpected",
	}); err == nil {
		t.Fatal("positional argument was accepted")
	}
}

func TestCancelOnEOFCancelsControllerContext(t *testing.T) {
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		cancelOnEOF(ctx, reader, cancel)
		close(done)
	}()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("EOF did not cancel controller")
	}
	if ctx.Err() == nil {
		t.Fatal("controller context remained active after EOF")
	}
}

func TestParentWatcherCancelsWhenControllerIdentityChanges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A deliberately impossible initial parent exercises the same transition
	// observed when the controller is SIGKILLed and the child is re-parented.
	go watchParent(ctx, os.Getpid()+1, cancel)
	select {
	case <-ctx.Done():
	case <-time.After(2 * parentWatchInterval):
		t.Fatal("parent watcher did not cancel after parent identity changed")
	}
}

func TestParentWatcherCancelsAlreadyOrphanedProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		watchParent(ctx, 1, cancel)
		close(done)
	}()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("orphan-at-start watcher did not cancel immediately")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("orphan-at-start watcher did not return")
	}
}

func TestRunBoundaryRejectsOrphanBeforePeerStateCreation(t *testing.T) {
	if err := requireLiveParent(1); err == nil {
		t.Fatal("orphan-at-start process was not synchronously rejected")
	}
	if err := requireLiveParent(2); err != nil {
		t.Fatalf("live parent was rejected: %v", err)
	}
}

func TestRunExitsAndRemovesDescriptorOnControllerEOF(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(root, "client.key")
	if err := os.WriteFile(clientPath, bytes.Repeat([]byte{0x55}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor := filepath.Join(root, "descriptor.json")
	args := []string{
		"--run-id", "0011223344556677",
		"--client-public-key", clientPath,
		"--private-dir", privateDir,
		"--descriptor", descriptor,
	}
	reader, writer := io.Pipe()
	var output lockedBuffer
	done := make(chan error, 1)
	go func() { done <- run(args, reader, &output) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(output.String(), "KYCLASH_SYSTEM_LAB_READY") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(output.String(), "KYCLASH_SYSTEM_LAB_READY") {
		_ = writer.Close()
		t.Fatalf("peer did not publish fixed ready status: %q", output.String())
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("system lab command did not exit after controller EOF")
	}
	if _, err := os.Stat(descriptor); !os.IsNotExist(err) {
		t.Fatalf("descriptor remained after EOF cleanup: %v", err)
	}
}

func TestProcessExitsOnParentDeathWhileStdinRemainsOpen(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(root, "client.key")
	if err := os.WriteFile(clientPath, bytes.Repeat([]byte{0x66}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor := filepath.Join(root, "descriptor.json")
	pidPath := filepath.Join(root, "child.pid")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	helper := exec.Command(os.Args[0], "-test.run=^TestSystemLabParentHelper$")
	helper.ExtraFiles = []*os.File{reader}
	helper.Env = append(os.Environ(),
		"KYCLASH_SYSTEM_LAB_PARENT_HELPER=1",
		"KYCLASH_SYSTEM_LAB_RUN_ID=1122334455667788",
		"KYCLASH_SYSTEM_LAB_CLIENT="+clientPath,
		"KYCLASH_SYSTEM_LAB_PRIVATE="+privateDir,
		"KYCLASH_SYSTEM_LAB_DESCRIPTOR="+descriptor,
		"KYCLASH_SYSTEM_LAB_PID_FILE="+pidPath,
	)
	if err := helper.Run(); err != nil {
		reader.Close()
		t.Fatal(err)
	}
	reader.Close()
	payload, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(payload)))
	if err != nil || pid <= 1 {
		t.Fatalf("invalid child PID record: %q", payload)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		processErr := syscall.Kill(pid, 0)
		_, descriptorErr := os.Stat(descriptor)
		if processErr != nil && os.IsNotExist(descriptorErr) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("child %d or descriptor remained after parent death with stdin held open", pid)
}

func TestSystemLabParentHelper(t *testing.T) {
	if os.Getenv("KYCLASH_SYSTEM_LAB_PARENT_HELPER") != "1" {
		t.Skip("parent helper only")
	}
	reader := os.NewFile(3, "system-lab-held-stdin")
	if reader == nil {
		t.Fatal("inherited stdin pipe is unavailable")
	}
	defer reader.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestSystemLabChildHelper$")
	child.Stdin = reader
	child.Env = append(os.Environ(), "KYCLASH_SYSTEM_LAB_CHILD_HELPER=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	descriptor := os.Getenv("KYCLASH_SYSTEM_LAB_DESCRIPTOR")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if info, err := os.Stat(descriptor); err == nil && info.Mode().IsRegular() {
			break
		}
		if time.Now().After(deadline) {
			_ = child.Process.Kill()
			t.Fatal("child did not publish its descriptor")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := os.WriteFile(
		os.Getenv("KYCLASH_SYSTEM_LAB_PID_FILE"),
		[]byte(strconv.Itoa(child.Process.Pid)+"\n"),
		0o600,
	); err != nil {
		_ = child.Process.Kill()
		t.Fatal(err)
	}
	// Returning terminates this helper process without waiting for the child.
	// The outer test deliberately keeps the pipe writer open, so only the
	// parent-identity watcher can terminate the child.
}

func TestSystemLabChildHelper(t *testing.T) {
	if os.Getenv("KYCLASH_SYSTEM_LAB_CHILD_HELPER") != "1" {
		t.Skip("child helper only")
	}
	args := []string{
		"--run-id", os.Getenv("KYCLASH_SYSTEM_LAB_RUN_ID"),
		"--client-public-key", os.Getenv("KYCLASH_SYSTEM_LAB_CLIENT"),
		"--private-dir", os.Getenv("KYCLASH_SYSTEM_LAB_PRIVATE"),
		"--descriptor", os.Getenv("KYCLASH_SYSTEM_LAB_DESCRIPTOR"),
	}
	if err := run(args, os.Stdin, io.Discard); err != nil {
		t.Fatal(err)
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (buffer *lockedBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.Buffer.Write(data)
}

func (buffer *lockedBuffer) WriteString(value string) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.Buffer.WriteString(value)
}

func (buffer *lockedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.Buffer.String()
}
