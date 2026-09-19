package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
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

// DefaultBridgeInterface 是未在 agent 配置中指定 bridge_interface 时使用的默认网桥。
const DefaultBridgeInterface = "incus0"

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

type stagedDNSProfile struct {
	MAC, configPath, pidPath string
	Port                     int
	BlockDoT                 bool
}

type dnsRollout struct {
	dir      string
	profiles []stagedDNSProfile
}

func Apply(ctx context.Context, bundle panel.NetworkPolicyBundle, bridgeInterface string) Status {
	status := Status{Revision: bundle.Revision}
	if err := apply(ctx, bundle, bridgeInterface); err != nil {
		status.Error = err.Error()
		return status
	}
	status.Applied = true
	return status
}

func apply(ctx context.Context, bundle panel.NetworkPolicyBundle, bridgeInterface string) error {
	// configured 为空表示由 agent 自动探测实际网桥（审查项 P2-06 收尾）
	configured := strings.TrimSpace(bridgeInterface)
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
	// DNS 策略存在时确定 dnsmasq 绑定与 input 链放行使用的网桥：
	// 显式配置优先；未配置时从实例 MAC 所在网桥自动探测，失败再回退默认值，
	// 避免 bridge_interface 与实际网桥名不一致导致 DNS 策略静默失效。
	bridgeName := configured
	if bridgeName == "" && len(profiles) > 0 {
		macs := make([]string, 0, len(profiles))
		for mac := range profiles {
			macs = append(macs, mac)
		}
		if detected := detectBridgeInterface(ctx, macs); detected != "" {
			bridgeName = detected
			log.Printf("network policy: detected bridge interface %q from instance MACs", bridgeName)
		} else {
			bridgeName = DefaultBridgeInterface
			log.Printf("network policy: could not detect bridge interface, falling back to %q", bridgeName)
		}
	}
	rollout, err := prepareDNSRollout(stateDir, profiles, bridgeName)
	if err != nil {
		return err
	}
	if err := startDNSRollout(ctx, rollout); err != nil {
		stopDNSRollout(ctx, rollout)
		os.RemoveAll(rollout.dir)
		return err
	}
	dnsRules := []string{}
	dotRules := []string{}
	for _, profile := range rollout.profiles {
		dnsRules = append(dnsRules, fmt.Sprintf("ether saddr %s udp dport 53 redirect to :%d", profile.MAC, profile.Port), fmt.Sprintf("ether saddr %s tcp dport 53 redirect to :%d", profile.MAC, profile.Port))
		if profile.BlockDoT {
			dotRules = append(dotRules, fmt.Sprintf("ether saddr %s tcp dport 853 counter reject", profile.MAC))
		}
	}
	// input 链（审查项 P2-06）：dnsmasq 监听端口只允许来自网桥与本机的访问，
	// 其他接口（含公网）对这些端口的入站一律丢弃。prerouting redirect 之后的
	// 本机投递会经过 input 链，因此该规则不会影响实例的 DNS 劫持转发。
	inputLines := []string{" chain input { type filter hook input priority -10; policy accept;", ` iifname "lo" accept`}
	for _, profile := range rollout.profiles {
		inputLines = append(inputLines,
			fmt.Sprintf(" iifname %q udp dport %d counter accept", bridgeName, profile.Port),
			fmt.Sprintf(" iifname %q tcp dport %d counter accept", bridgeName, profile.Port),
			fmt.Sprintf(" udp dport %d counter drop", profile.Port),
			fmt.Sprintf(" tcp dport %d counter drop", profile.Port),
		)
	}
	inputLines = append(inputLines, " }")

	lines := []string{"table inet incudal_managed_policy {", " chain forward { type filter hook forward priority -10; policy accept;"}
	lines = append(lines, ipv4Blocks...)
	lines = append(lines, ipv6Blocks...)
	lines = append(lines, transportBlocks...)
	lines = append(lines, pingBlocks...)
	lines = append(lines, dotRules...)
	lines = append(lines, " }")
	lines = append(lines, inputLines...)
	lines = append(lines, " chain prerouting { type nat hook prerouting priority -105; policy accept;")
	lines = append(lines, dnsRules...)
	lines = append(lines, " }", "}")
	if err := replaceNftTable(ctx, strings.Join(lines, "\n")+"\n"); err != nil {
		stopDNSRollout(ctx, rollout)
		os.RemoveAll(rollout.dir)
		return err
	}
	return stopOldDNSExcept(ctx, rollout.dir)
}

func prepareDNSRollout(root string, profiles map[string]*dnsProfile, bridgeInterface string) (dnsRollout, error) {
	rollout := dnsRollout{}
	if strings.TrimSpace(bridgeInterface) == "" {
		bridgeInterface = DefaultBridgeInterface
	}
	macs := make([]string, 0, len(profiles))
	for mac := range profiles {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	for _, mac := range macs {
		if len(unique(profiles[mac].Upstreams)) == 0 {
			return rollout, fmt.Errorf("DNS policy for %s has no configured upstream", mac)
		}
	}
	dir, err := os.MkdirTemp(root, "generation-")
	if err != nil {
		return rollout, err
	}
	rollout.dir = dir
	port := 10000 + int(time.Now().UnixNano()%40000)
	for index, mac := range macs {
		profile := profiles[mac]
		// 启动前探测端口占用（审查项 P2-06）：TCP/UDP 通配绑定任一失败即跳过，
		// 避免随机端口撞上宿主机现有服务导致 dnsmasq 绑定失败。
		for !isPortFree(port) {
			port++
			if port >= 65535 {
				os.RemoveAll(dir)
				return dnsRollout{}, fmt.Errorf("no free TCP/UDP port available for dnsmasq profile %d", index)
			}
		}
		configPort := port
		port++
		config := []string{
			"no-resolv", "no-hosts", "bind-dynamic",
			// 仅绑定 Incus 网桥（审查项 P2-06）：不再监听 0.0.0.0，
			// 防止 dnsmasq 变成公网可访问的 DNS 转发器被滥用或用于放大攻击
			"interface=" + bridgeInterface,
			"port=" + strconv.Itoa(configPort),
			"cache-size=1000", "domain-needed", "bogus-priv",
		}
		for _, upstream := range unique(profile.Upstreams) {
			config = append(config, "server="+upstream)
		}
		config = append(config, unique(profile.Lines)...)
		configPath := filepath.Join(dir, fmt.Sprintf("dns-%d.conf", index))
		pidPath := filepath.Join(dir, fmt.Sprintf("dns-%d.pid", index))
		if err := os.WriteFile(configPath, []byte(strings.Join(config, "\n")+"\n"), 0600); err != nil {
			os.RemoveAll(dir)
			return dnsRollout{}, err
		}
		rollout.profiles = append(rollout.profiles, stagedDNSProfile{MAC: mac, configPath: configPath, pidPath: pidPath, Port: configPort, BlockDoT: profile.BlockDoT})
	}
	return rollout, nil
}

// isPortFree 尽力探测端口是否空闲。仅缩小撞端口的概率窗口，真正的冲突
// 仍会在 dnsmasq 启动时暴露，并由 apply 的整体回滚兜底。
func isPortFree(port int) bool {
	tcpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	tcpListener.Close()

	udpConn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	udpConn.Close()
	return true
}

// detectBridgeInterface 通过 bridge fdb show 反查目标实例 MAC 所在的网桥。
// 实例未运行（FDB 无表项）或 bridge 命令不可用时返回空字符串。
func detectBridgeInterface(ctx context.Context, macs []string) string {
	if len(macs) == 0 {
		return ""
	}
	wanted := make(map[string]bool, len(macs))
	for _, mac := range macs {
		wanted[strings.ToLower(mac)] = true
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(cmdCtx, "bridge", "fdb", "show").Output()
	if err != nil {
		return ""
	}
	return pickBridgeFromFdbOutput(string(output), wanted)
}

// pickBridgeFromFdbOutput 解析 `bridge fdb show` 输出，选出目标实例 MAC 所在的网桥。
// 行示例：`00:11:22:33:44:55 dev vethabc123 master incus0 permanent`。
// 优先取 master（网桥设备），无 master 时退回 dev（网桥端口）；出现次数最多者胜出，
// 并发同名时按字典序保持确定性。
func pickBridgeFromFdbOutput(output string, wanted map[string]bool) string {
	weights := map[string]int{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !wanted[strings.ToLower(fields[0])] {
			continue
		}
		hasMaster := false
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "master":
				weights[fields[i+1]] += 2
				hasMaster = true
			case "dev":
				if !hasMaster {
					weights[fields[i+1]] += 1
				}
			}
		}
	}

	names := make([]string, 0, len(weights))
	for name := range weights {
		names = append(names, name)
	}
	sort.Strings(names)

	best := ""
	bestWeight := 0
	for _, name := range names {
		if weights[name] > bestWeight && isSaneInterfaceName(name) {
			best = name
			bestWeight = weights[name]
		}
	}
	return best
}

// isSaneInterfaceName 校验探测到的设备名可安全嵌入 dnsmasq 配置与 nftables 规则
// （Linux 接口名最长 15 字符且不含空白/引号；此处为纵深防御）。
func isSaneInterfaceName(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func startDNSRollout(ctx context.Context, rollout dnsRollout) error {
	for _, profile := range rollout.profiles {
		checkCtx, cancelCheck := context.WithTimeout(ctx, 10*time.Second)
		check := exec.CommandContext(checkCtx, "dnsmasq", "--test", "--conf-file="+profile.configPath)
		if output, err := check.CombinedOutput(); err != nil {
			cancelCheck()
			return fmt.Errorf("validate dnsmasq profile: %v: %s", err, strings.TrimSpace(string(output)))
		}
		cancelCheck()
		commandCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		command := exec.CommandContext(commandCtx, "dnsmasq", "--conf-file="+profile.configPath, "--pid-file="+profile.pidPath)
		if output, err := command.CombinedOutput(); err != nil {
			cancel()
			return fmt.Errorf("start dnsmasq profile: %v: %s", err, strings.TrimSpace(string(output)))
		}
		cancel()
		if _, err := os.Stat(profile.pidPath); err != nil {
			return fmt.Errorf("dnsmasq profile did not create pid file: %w", err)
		}
	}
	return nil
}

func stopDNSRollout(ctx context.Context, rollout dnsRollout) {
	for _, profile := range rollout.profiles {
		stopDNSPid(ctx, profile.pidPath)
	}
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
func stopDNSPid(ctx context.Context, path string) {
	data, _ := os.ReadFile(path)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	if pid > 1 {
		killCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = exec.CommandContext(killCtx, "kill", strconv.Itoa(pid)).Run()
		cancel()
	}
	os.Remove(path)
}

func stopOldDNSExcept(ctx context.Context, keepDir string) error {
	entries, _ := filepath.Glob(filepath.Join(stateDir, "dns-*.pid"))
	generationEntries, _ := filepath.Glob(filepath.Join(stateDir, "generation-*", "dns-*.pid"))
	entries = append(entries, generationEntries...)
	for _, path := range entries {
		if filepath.Dir(path) != keepDir {
			stopDNSPid(ctx, path)
		}
	}
	configs, _ := filepath.Glob(filepath.Join(stateDir, "dns-*.conf"))
	for _, path := range configs {
		os.Remove(path)
	}
	generations, _ := filepath.Glob(filepath.Join(stateDir, "generation-*"))
	for _, dir := range generations {
		if dir != keepDir {
			os.RemoveAll(dir)
		}
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
