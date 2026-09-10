package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildDNSRolloutValidatesBeforeReplacingOldConfiguration(t *testing.T) {
	root := t.TempDir()
	oldState := filepath.Join(root, "active")
	if err := os.MkdirAll(oldState, 0700); err != nil {
		t.Fatal(err)
	}
	oldConfig := filepath.Join(oldState, "dns-0.conf")
	if err := os.WriteFile(oldConfig, []byte("old-policy\n"), 0600); err != nil {
		t.Fatal(err)
	}

	profiles := map[string]*dnsProfile{
		"00:11:22:33:44:55": {MAC: "00:11:22:33:44:55"},
	}
	_, err := prepareDNSRollout(root, profiles)
	if err == nil || !strings.Contains(err.Error(), "no configured upstream") {
		t.Fatalf("expected upstream validation failure, got %v", err)
	}
	content, readErr := os.ReadFile(oldConfig)
	if readErr != nil {
		t.Fatalf("old configuration was removed: %v", readErr)
	}
	if string(content) != "old-policy\n" {
		t.Fatalf("old configuration changed: %q", content)
	}
}

func TestDNSRolloutUsesGenerationSpecificPortsAndPaths(t *testing.T) {
	root := t.TempDir()
	profiles := map[string]*dnsProfile{
		"00:11:22:33:44:55": {MAC: "00:11:22:33:44:55", Upstreams: []string{"1.1.1.1"}},
	}
	rollout, err := prepareDNSRollout(root, profiles)
	if err != nil {
		t.Fatal(err)
	}
	if rollout.dir == root || !strings.HasPrefix(rollout.dir, root+string(os.PathSeparator)) {
		t.Fatalf("expected generation directory below state root, got %q", rollout.dir)
	}
	if rollout.profiles[0].Port < 10000 {
		t.Fatalf("expected non-legacy generation port, got %d", rollout.profiles[0].Port)
	}
	if _, err := os.Stat(rollout.profiles[0].configPath); err != nil {
		t.Fatalf("staged config missing: %v", err)
	}
}
