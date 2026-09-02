package report

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const securityNftTimeout = 10 * time.Second

type nftDocument struct {
	Nftables []struct {
		Set *struct {
			Name string `json:"name"`
			Elem []struct {
				Elem struct {
					Val struct {
						Concat []string `json:"concat"`
					} `json:"val"`
					Expires int `json:"expires"`
				} `json:"elem"`
			} `json:"elem"`
		} `json:"set"`
	} `json:"nftables"`
}

func collectSecurityEvents() []any {
	events := make([]any, 0)
	ctx, cancel := context.WithTimeout(context.Background(), securityNftTimeout)
	defer cancel()
	for _, spec := range []struct{ setName, family, eventType, action string }{
		{"blocked_v4", "ipv4", "single_target_pps_block", "blocked_source_mac_destination_pair"},
		{"blocked_v6", "ipv6", "single_target_pps_block", "blocked_source_mac_destination_pair"},
		{"observed_v4", "ipv4", "single_target_pps_observation", "observed_source_mac_destination_pair"},
		{"observed_v6", "ipv6", "single_target_pps_observation", "observed_source_mac_destination_pair"},
	} {
		output, err := exec.CommandContext(ctx, "nft", "-j", "list", "set", "inet", "incudal_pps_guard", spec.setName).Output()
		if err != nil {
			continue
		}
		var document nftDocument
		if json.Unmarshal(output, &document) != nil {
			continue
		}
		for _, item := range document.Nftables {
			if item.Set == nil || item.Set.Name != spec.setName {
				continue
			}
			for _, entry := range item.Set.Elem {
				if len(entry.Elem.Val.Concat) != 2 {
					continue
				}
				events = append(events, map[string]any{
					"type":             spec.eventType,
					"family":           spec.family,
					"sourceMac":        entry.Elem.Val.Concat[0],
					"destinationIp":    entry.Elem.Val.Concat[1],
					"expiresInSeconds": entry.Elem.Expires,
					"thresholdPps":     readGuardInteger("PPS_SINGLE_TARGET_LIMIT", 20000),
					"instanceLimitPps": readGuardInteger("PPS_LIMIT", 20000),
					"action":           spec.action,
				})
			}
		}
	}
	return events
}

func readGuardInteger(key string, fallback int) int {
	content, err := os.ReadFile("/etc/incudal/pps-guard.conf")
	if err != nil {
		return fallback
	}
	prefix := key + "="
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, prefix) {
			value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
			if err == nil && value > 0 {
				return value
			}
		}
	}
	return fallback
}
