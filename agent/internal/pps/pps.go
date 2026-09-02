package pps

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	guardPath                 = "/usr/local/sbin/incudal-pps-guard"
	configPath                = "/etc/incudal/pps-guard.conf"
	minimumPPS                = 20000
	maximumPPS                = 500000
	defaultObserveSecs        = 120
	ppsTableCheckTimeout      = 5 * time.Second
	minimumForwardRuleCount   = 8
	minimumInstanceRuleCount  = 1
)

//go:embed guard.sh
var guardScript []byte

// Sync upgrades the installed PPS guard and reloads its nftables table.
// An absent config means PPS protection is disabled and is intentionally a no-op.
func Sync(ctx context.Context) error {
	return syncAt(ctx, configPath, guardPath)
}

func syncAt(ctx context.Context, configFile string, scriptFile string) error {
	content, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read PPS config: %w", err)
	}

	normalized := normalizeConfig(string(content))
	configChanged := normalized != string(content)
	if configChanged {
		if err := writeAtomic(configFile, []byte(normalized), 0600); err != nil {
			return fmt.Errorf("update PPS config: %w", err)
		}
	}
	if err := os.Chmod(configFile, 0600); err != nil {
		return fmt.Errorf("secure PPS config: %w", err)
	}

	installedScript, scriptErr := os.ReadFile(scriptFile)
	scriptChanged := scriptErr != nil || !bytes.Equal(installedScript, guardScript)
	if scriptChanged {
		if err := writeAtomic(scriptFile, guardScript, 0755); err != nil {
			return fmt.Errorf("update PPS guard: %w", err)
		}
	} else if err := os.Chmod(scriptFile, 0755); err != nil {
		return fmt.Errorf("make PPS guard executable: %w", err)
	}
	if !configChanged && !scriptChanged && ppsTableHealthy(ctx) {
		return nil
	}

	commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(commandCtx, "/bin/bash", scriptFile)
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return fmt.Errorf("reload PPS guard: %w", err)
		}
		return fmt.Errorf("reload PPS guard: %w: %s", err, message)
	}
	if !ppsTableHealthy(ctx) {
		return fmt.Errorf("reload PPS guard completed but required nftables table/rules are missing")
	}
	return nil
}

func ppsTableHealthy(ctx context.Context) bool {
	checkCtx, cancel := context.WithTimeout(ctx, ppsTableCheckTimeout)
	defer cancel()

	output, err := exec.CommandContext(
		checkCtx,
		"nft", "-j", "list", "table", "inet", "incudal_pps_guard",
	).Output()
	if err != nil {
		return false
	}

	var document nftTableDocument
	if err := json.Unmarshal(output, &document); err != nil {
		return false
	}

	sets := map[string]bool{}
	chains := map[string]bool{}
	rules := map[string]int{}
	for _, item := range document.Nftables {
		if item.Set != nil {
			sets[item.Set.Name] = true
		}
		if item.Chain != nil {
			chains[item.Chain.Name] = true
		}
		if item.Rule != nil {
			rules[item.Rule.Chain]++
		}
	}
	for _, required := range []string{"blocked_v4", "blocked_v6", "observed_v4", "observed_v6"} {
		if !sets[required] {
			return false
		}
	}
	return chains["forward"] && chains["instance_pps_limit"] &&
		rules["forward"] >= minimumForwardRuleCount &&
		rules["instance_pps_limit"] >= minimumInstanceRuleCount
}

type nftTableDocument struct {
	Nftables []struct {
		Set *struct {
			Name string `json:"name"`
		} `json:"set"`
		Chain *struct {
			Name string `json:"name"`
		} `json:"chain"`
		Rule *struct {
			Chain string `json:"chain"`
		} `json:"rule"`
	} `json:"nftables"`
}

func normalizeConfig(content string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.TrimRight(content, "\n")
	lines := strings.Split(content, "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}

	updates := map[string]string{
		"PPS_MIN_LIMIT":             strconv.Itoa(minimumPPS),
		"PPS_OBSERVE_SECONDS":       strconv.Itoa(defaultObserveSecs),
	}
	seen := make(map[string]bool, len(updates)+2)

	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		for _, key := range []string{"PPS_LIMIT", "PPS_SINGLE_TARGET_LIMIT", "PPS_MIN_LIMIT", "PPS_OBSERVE_SECONDS"} {
			prefix := key + "="
			if !strings.HasPrefix(trimmed, prefix) {
				continue
			}

			value := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
			switch key {
			case "PPS_LIMIT", "PPS_SINGLE_TARGET_LIMIT":
				parsed, parseErr := strconv.Atoi(value)
				if parseErr != nil || parsed < minimumPPS {
					parsed = minimumPPS
				}
				if parsed > maximumPPS {
					parsed = maximumPPS
				}
				updates[key] = strconv.Itoa(parsed)
			case "PPS_MIN_LIMIT":
				updates[key] = strconv.Itoa(minimumPPS)
			case "PPS_OBSERVE_SECONDS":
				parsed, parseErr := strconv.Atoi(value)
				if parseErr != nil || parsed < 1 {
					parsed = defaultObserveSecs
				}
				updates[key] = strconv.Itoa(parsed)
			}
			lines[index] = key + "=" + updates[key]
			seen[key] = true
			break
		}
	}

	for _, key := range []string{"PPS_MIN_LIMIT", "PPS_OBSERVE_SECONDS"} {
		if !seen[key] {
			lines = append(lines, key+"="+updates[key])
		}
	}

	return strings.Join(lines, "\n") + "\n"
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".incudal-pps-sync-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
