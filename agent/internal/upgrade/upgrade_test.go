package upgrade

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"incudal-agent/internal/panel"
)

func TestApplyUpgradeReplacesBinaryAndRestarts(t *testing.T) {
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "incudal-agent")
	if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatalf("write current binary: %v", err)
	}

	nextBinary := currentTestExecutable(t)
	packageBytes := gzipBytes(t, nextBinary)
	sha := sha256Hex(packageBytes)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(packageBytes)
	}))
	defer server.Close()

	restarted := false
	runner := Runner{
		BinaryPath:       binaryPath,
		BackupPath:       binaryPath + ".bak",
		LockPath:         filepath.Join(tempDir, "upgrade.lock"),
		ServiceName:      "incudal-agent",
		AllowedBaseURL:   server.URL,
		HTTPClient:       server.Client(),
		MaxDownloadBytes: int64(len(packageBytes) + 1),
		MaxBinaryBytes:   int64(len(nextBinary) + 1),
		Restart: func(_ context.Context, serviceName string) error {
			if serviceName != "incudal-agent" {
				t.Fatalf("unexpected service name: %s", serviceName)
			}
			restarted = true
			return nil
		},
	}

	err := runner.Apply(context.Background(), panel.UpgradeInstruction{
		Available: true,
		Version:   "v2",
		URL:       server.URL + "/incudal-agent-linux-amd64.gz",
		SHA256:    sha,
		Gzip:      true,
	}, "v1")
	if err != nil {
		t.Fatalf("apply upgrade: %v", err)
	}
	if !restarted {
		t.Fatalf("restart was not called")
	}

	actual, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read replaced binary: %v", err)
	}
	if string(actual) != string(nextBinary) {
		t.Fatalf("binary mismatch: %q", string(actual))
	}

	backup, err := os.ReadFile(binaryPath + ".bak")
	if err != nil {
		t.Fatalf("read backup binary: %v", err)
	}
	if string(backup) != "old-binary" {
		t.Fatalf("backup mismatch: %q", string(backup))
	}
}

func TestApplyUpgradeRejectsBadSHA(t *testing.T) {
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "incudal-agent")
	if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatalf("write current binary: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("payload"))
	}))
	defer server.Close()

	restarted := false
	runner := Runner{
		BinaryPath:       binaryPath,
		BackupPath:       binaryPath + ".bak",
		LockPath:         filepath.Join(tempDir, "upgrade.lock"),
		AllowedBaseURL:   server.URL,
		HTTPClient:       server.Client(),
		MaxDownloadBytes: int64(len([]byte("payload")) + 1),
		Restart: func(context.Context, string) error {
			restarted = true
			return nil
		},
	}

	err := runner.Apply(context.Background(), panel.UpgradeInstruction{
		Available: true,
		Version:   "v2",
		URL:       server.URL + "/incudal-agent-linux-amd64.gz",
		SHA256:    "0000000000000000000000000000000000000000000000000000000000000000",
		Gzip:      true,
	}, "v1")
	if err == nil {
		t.Fatalf("expected sha mismatch")
	}
	if restarted {
		t.Fatalf("restart should not be called")
	}

	current, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read current binary: %v", err)
	}
	if string(current) != "old-binary" {
		t.Fatalf("current binary should stay unchanged: %q", string(current))
	}
}

func TestApplyUpgradeRollsBackWhenRestartFails(t *testing.T) {
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "incudal-agent")
	if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatalf("write current binary: %v", err)
	}

	nextBinary := currentTestExecutable(t)
	packageBytes := gzipBytes(t, nextBinary)
	sha := sha256Hex(packageBytes)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(packageBytes)
	}))
	defer server.Close()

	restartCalls := 0
	runner := Runner{
		BinaryPath:       binaryPath,
		BackupPath:       binaryPath + ".bak",
		LockPath:         filepath.Join(tempDir, "upgrade.lock"),
		ServiceName:      "incudal-agent",
		AllowedBaseURL:   server.URL,
		HTTPClient:       server.Client(),
		MaxDownloadBytes: int64(len(packageBytes) + 1),
		MaxBinaryBytes:   int64(len(nextBinary) + 1),
		Restart: func(context.Context, string) error {
			restartCalls++
			if restartCalls == 1 {
				return errors.New("restart failed")
			}
			return nil
		},
	}

	err := runner.Apply(context.Background(), panel.UpgradeInstruction{
		Available: true,
		Version:   "v2",
		URL:       server.URL + "/incudal-agent-linux-amd64.gz",
		SHA256:    sha,
		Gzip:      true,
	}, "v1")
	if err == nil {
		t.Fatalf("expected restart error")
	}

	actual, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read replaced binary: %v", err)
	}
	if string(actual) != "old-binary" {
		t.Fatalf("binary should be rolled back after restart failure: %q", string(actual))
	}
	if restartCalls != 2 {
		t.Fatalf("expected two restart attempts, got %d", restartCalls)
	}
}

func TestApplyUpgradeRejectsOversizedDecompressedBinary(t *testing.T) {
	nextBinary := currentTestExecutable(t)
	testUpgradeRejected(t, gzipBytes(t, nextBinary), true, int64(len(nextBinary)-1), "decompressed")
}

func TestApplyUpgradeRejectsInvalidBinaryFormat(t *testing.T) {
	testUpgradeRejected(t, []byte("not-an-executable"), false, 1024, "executable format")
}

func TestApplyUpgradeRejectsWrongArchitecture(t *testing.T) {
	binary := currentTestExecutable(t)
	if len(binary) < 20 || string(binary[:4]) != "\x7fELF" {
		t.Skip("test executable is not ELF")
	}
	foreignMachine := byte(183)
	if runtime.GOARCH == "arm64" {
		foreignMachine = 62
	}
	binary[18], binary[19] = foreignMachine, 0
	testUpgradeRejected(t, binary, false, int64(len(binary)+1), "architecture")
}

func testUpgradeRejected(t *testing.T, packageBytes []byte, compressed bool, maxBinaryBytes int64, expected string) {
	t.Helper()
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "incudal-agent")
	if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write(packageBytes)
	}))
	defer server.Close()
	runner := Runner{
		BinaryPath: binaryPath, BackupPath: binaryPath + ".bak", LockPath: filepath.Join(tempDir, "upgrade.lock"),
		AllowedBaseURL: server.URL, HTTPClient: server.Client(), MaxDownloadBytes: int64(len(packageBytes) + 1),
		MaxBinaryBytes: maxBinaryBytes,
	}
	err := runner.Apply(context.Background(), panel.UpgradeInstruction{
		Available: true, Version: "v2", URL: server.URL + "/agent", SHA256: sha256Hex(packageBytes), Gzip: compressed,
	}, "v1")
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte(expected)) {
		t.Fatalf("expected %q error, got %v", expected, err)
	}
}

func currentTestExecutable(t *testing.T) []byte {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestApplyUpgradeRejectsDifferentOrigin(t *testing.T) {
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "incudal-agent")
	if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatalf("write current binary: %v", err)
	}

	runner := Runner{
		BinaryPath:     binaryPath,
		BackupPath:     binaryPath + ".bak",
		LockPath:       filepath.Join(tempDir, "upgrade.lock"),
		AllowedBaseURL: "https://panel.example",
		Restart: func(context.Context, string) error {
			t.Fatalf("restart should not be called")
			return nil
		},
	}

	err := runner.Apply(context.Background(), panel.UpgradeInstruction{
		Available: true,
		Version:   "v2",
		URL:       "https://evil.example/incudal-agent-linux-amd64.gz",
		SHA256:    "0000000000000000000000000000000000000000000000000000000000000000",
		Gzip:      true,
	}, "v1")
	if err == nil {
		t.Fatalf("expected origin validation error")
	}
}

func gzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()

	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buffer.Bytes()
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
