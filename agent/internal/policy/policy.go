package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"incudal-agent/internal/panel"
)

const stateDir = "/etc/incudal-agent/network-policy"

var macPattern = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
var domainPattern = regexp.MustCompile(`^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type Status struct {
	Revision string `json:"revision"`
	Applied  bool   `json:"applied"`
	Error    string `json:"error,omitempty"`
}
type dnsProfile struct {
	MAC              string
	Upstreams, Lines []string
	BlockDoT         bool
	Port             int
}

func Apply(ctx context.Context, bundle panel.NetworkPolicyBundle) Status {
	status := Status{Revision: bundle.Revision}
	if err := apply(ctx, bundle); err != nil {
		status.Error = err.Error()
		return status
	}
	status.Applied = true
	return status
}

func apply(ctx context.Context, bundle panel.NetworkPolicyBundle) error {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	// Do not install a partially effective bundle. The panel includes every
	// selected target even when its MAC is not currently known; treating that
	// as success would make the policy silently fail open for that instance.
	for _, item := range bundle.Policies {
		for _, target := range item.Targets {
			mac := strings.ToLower(strings.TrimSpace(target.MAC))
			if !macPattern.MatchString(mac) {
				return fmt.Errorf("network policy %d target %q is missing a valid MAC", item.ID, target.IncusID)
			}
		}
	}
	profiles := map[string]*dnsProfile{}
	ipv4Blocks, ipv6Blocks := []string{}, []string{}
	transportBlocks, pingBlocks := []string{}, []string{}
	for _, item := range bundle.Policies {
		for _, target := range item.Targets {
			mac := strings.ToLower(strings.TrimSpace(target.MAC))
			if !macPattern.MatchString(mac) {
				continue
			}
			switch item.Type {
			case "ip_block":
				for _, cidr := range readStrings(item.Config["cidrs"]) {
					if ip, _, err := net.ParseCIDR(normalizeCIDR(cidr)); err == nil {
						rule := fmt.Sprintf("ether saddr %s %s daddr %s counter drop", mac, map[bool]string{true: "ip", false: "ip6"}[ip.To4() != nil], cidr)
						if ip.To4() != nil {
							ipv4Blocks = append(ipv4Blocks, rule)
						} else {
							ipv6Blocks = append(ipv6Blocks, rule)
						}
					}
				}
			case "udp_block":
				transportBlocks = append(transportBlocks,
					fmt.Sprintf("ether saddr %s udp counter drop", mac),
					fmt.Sprintf("ether daddr %s udp counter drop", mac),
				)
			case "ping_block":
				pingBlocks = append(pingBlocks,
					fmt.Sprintf("ether saddr %s icmp type echo-request counter drop", mac),
					fmt.Sprintf("ether daddr %s icmp type echo-request counter drop", mac),
					fmt.Sprintf("ether saddr %s icmpv6 type echo-request counter drop", mac),
					fmt.Sprintf("ether daddr %s icmpv6 type echo-request counter drop", mac),
				)
			case "dns_lock", "dns_override":
				profile := profiles[mac]
				if profile == nil {
					profile = &dnsProfile{MAC: mac}
					profiles[mac] = profile
				}
				for _, upstream := range readStrings(item.Config["upstreams"]) {
					if net.ParseIP(upstream) != nil {
						profile.Upstreams = append(profile.Upstreams, upstream)
					}
				}
				if item.Config["blockDot"] == true {
					profile.BlockDoT = true
				}
				if item.Type == "dns_override" {
					action, _ := item.Config["action"].(string)
					domains := readStrings(item.Config["domains"])
					addresses := readStrings(item.Config["addresses"])
					for _, domain := range domains {
						domain = strings.ToLower(strings.TrimPrefix(domain, "*."))
						if !domainPattern.MatchString(domain) {
							continue
						}
						switch action {
						case "nxdomain":
							profile.Lines = append(profile.Lines, "address=/"+domain+"/")
						case "zero":
							profile.Lines = append(profile.Lines, "address=/"+domain+"/0.0.0.0", "address=/"+domain+"/::")
						default:
							for _, address := range addresses {
								if net.ParseIP(address) != nil {
									profile.Lines = append(profile.Lines, "address=/"+domain+"/"+address)
								}
							}
						}
					}
				}
			}
		}
	}
	if len(profiles) > 0 {
		if _, err := exec.LookPath("dnsmasq"); err != nil {
			return fmt.Errorf("dnsmasq is required for enabled DNS policies")
		}
	}
	if err := stopOldDNS(ctx); err != nil {
		return err
	}
	macs := make([]string, 0, len(profiles))
	for mac := range profiles {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	dnsRules := []string{}
	dotRules := []string{}
	for index, mac := range macs {
		profile := profiles[mac]
		profile.Port = 5353 + index
		profile.Upstreams = unique(profile.Upstreams)
		if len(profile.Upstreams) == 0 {
			return fmt.Errorf("DNS policy for %s has no configured upstream", mac)
		}
		config := []string{"no-resolv", "no-hosts", "bind-dynamic", "listen-address=0.0.0.0", "port=" + strconv.Itoa(profile.Port), "cache-size=1000", "domain-needed", "bogus-priv"}
		for _, upstream := range profile.Upstreams {
			config = append(config, "server="+upstream)
		}
		config = append(config, unique(profile.Lines)...)
		path := filepath.Join(stateDir, fmt.Sprintf("dns-%d.conf", index))
		if err := os.WriteFile(path, []byte(strings.Join(config, "\n")+"\n"), 0600); err != nil {
			return err
		}
		pidPath := filepath.Join(stateDir, fmt.Sprintf("dns-%d.pid", index))
		commandCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		command := exec.CommandContext(commandCtx, "dnsmasq", "--conf-file="+path, "--pid-file="+pidPath)
		if output, err := command.CombinedOutput(); err != nil {
			cancel()
			return fmt.Errorf("start dnsmasq profile: %v: %s", err, strings.TrimSpace(string(output)))
		}
		cancel()
		dnsRules = append(dnsRules, fmt.Sprintf("ether saddr %s udp dport 53 redirect to :%d", mac, profile.Port), fmt.Sprintf("ether saddr %s tcp dport 53 redirect to :%d", mac, profile.Port))
		if profile.BlockDoT {
			dotRules = append(dotRules, fmt.Sprintf("ether saddr %s tcp dport 853 counter reject", mac))
		}
	}
	lines := []string{"table inet incudal_managed_policy {", " chain forward { type filter hook forward priority -10; policy accept;"}
	lines = append(lines, ipv4Blocks...)
	lines = append(lines, ipv6Blocks...)
	lines = append(lines, transportBlocks...)
	lines = append(lines, pingBlocks...)
	lines = append(lines, dotRules...)
	lines = append(lines, " }", " chain prerouting { type nat hook prerouting priority -105; policy accept;")
	lines = append(lines, dnsRules...)
	lines = append(lines, " }", "}")
	return replaceNftTable(ctx, strings.Join(lines, "\n")+"\n")
}

func replaceNftTable(ctx context.Context, rules string) error {
	// nft -f applies the whole document as one transaction. Keeping deletion in
	// the same document means a syntax/validation failure preserves the previous
	// working table instead of leaving the host unprotected.
	checkCtx, cancelCheck := context.WithTimeout(ctx, 10*time.Second)
	tableExists := exec.CommandContext(checkCtx, "nft", "list", "table", "inet", "incudal_managed_policy").Run() == nil
	cancelCheck()
	if tableExists {
		rules = "delete table inet incudal_managed_policy\n" + rules
	}
	commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("load nft policy: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
func stopOldDNS(ctx context.Context) error {
	entries, _ := filepath.Glob(filepath.Join(stateDir, "dns-*.pid"))
	for _, path := range entries {
		data, _ := os.ReadFile(path)
		pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		if pid > 1 {
			killCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = exec.CommandContext(killCtx, "kill", strconv.Itoa(pid)).Run()
			cancel()
		}
		os.Remove(path)
	}
	configs, _ := filepath.Glob(filepath.Join(stateDir, "dns-*.conf"))
	for _, path := range configs {
		os.Remove(path)
	}
	return nil
}
func readStrings(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		if direct, ok := value.([]string); ok {
			return direct
		}
		return nil
	}
	out := []string{}
	for _, item := range raw {
		if text, ok := item.(string); ok {
			out = append(out, strings.TrimSpace(text))
		}
	}
	return out
}
func unique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
func normalizeCIDR(value string) string {
	if strings.Contains(value, "/") {
		return value
	}
	if ip := net.ParseIP(value); ip != nil && ip.To4() != nil {
		return value + "/32"
	}
	return value + "/128"
}
func StatusMap(status Status) map[string]any {
	data, _ := json.Marshal(status)
	var result map[string]any
	json.Unmarshal(data, &result)
	return result
}
