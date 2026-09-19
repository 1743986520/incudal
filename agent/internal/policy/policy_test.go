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
	_, err := prepareDNSRollout(root, profiles, "incus0")
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
	rollout, err := prepareDNSRollout(root, profiles, "incus0")
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

func TestDNSRolloutBindsBridgeInterfaceOnly(t *testing.T) {
	root := t.TempDir()
	profiles := map[string]*dnsProfile{
		"00:11:22:33:44:55": {MAC: "00:11:22:33:44:55", Upstreams: []string{"1.1.1.1"}},
	}
	rollout, err := prepareDNSRollout(root, profiles, "br-lan")
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(rollout.profiles[0].configPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if !strings.Contains(text, "interface=br-lan") {
		t.Fatalf("expected dnsmasq to bind the bridge interface only, got: %s", text)
	}
	if strings.Contains(text, "listen-address=0.0.0.0") {
		t.Fatalf("dnsmasq must not listen on all interfaces: %s", text)
	}
}

func TestPickBridgeFromFdbOutputPrefersMasterAndMajority(t *testing.T) {
	wanted := map[string]bool{
		"00:11:22:33:44:55": true,
		"aa:bb:cc:dd:ee:ff": true,
	}
	output := strings.Join([]string{
		"00:11:22:33:44:55 dev vethabc123 master incus0 permanent",
		"00:11:22:33:44:55 dev vethabc123 permanent",
		"aa:bb:cc:dd:ee:ff dev vethdef456 master incus0 permanent",
		"fe:00:11:22:33:44 dev eth0 permanent",
		"33:33:00:00:00:01 dev eth0 permanent",
	}, "\n")

	if got := pickBridgeFromFdbOutput(output, wanted); got != "incus0" {
		t.Fatalf("expected incus0, got %q", got)
	}
}

func TestPickBridgeFromFdbOutputFallsBackToDevAndIgnoresUnwanted(t *testing.T) {
	wanted := map[string]bool{"00:11:22:33:44:55": true}
	output := "00:11:22:33:44:55 dev br-private permanent"

	if got := pickBridgeFromFdbOutput(output, wanted); got != "br-private" {
		t.Fatalf("expected dev fallback br-private, got %q", got)
	}
	if got := pickBridgeFromFdbOutput("aa:aa:aa:aa:aa:aa dev eth0 permanent", wanted); got != "" {
		t.Fatalf("expected empty result for unwanted MACs, got %q", got)
	}
	if got := pickBridgeFromFdbOutput("00:11:22:33:44:55 dev evil;drop permanent", wanted); got != "" {
		t.Fatalf("expected unsafe interface name to be rejected, got %q", got)
	}
}
