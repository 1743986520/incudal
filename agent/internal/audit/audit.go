package audit

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"sync"
	"time"

	"incudal-agent/internal/panel"
)

type Scanner struct {
	mu      sync.Mutex
	cursor  int
	lastRun time.Time
}
type instanceRow struct{ Name, Status, Type string }

func (scanner *Scanner) Scan(ctx context.Context, config panel.MonitoringInstruction) []any {
	scanner.mu.Lock()
	defer scanner.mu.Unlock()
	if (!config.Enabled && !config.Force) || (!config.Force && !scanner.lastRun.IsZero() && time.Since(scanner.lastRun) < time.Duration(config.IntervalSeconds)*time.Second) {
		return nil
	}
	rows := listInstances(ctx)
	if len(rows) == 0 {
		return nil
	}
	batch := config.BatchSize
	if batch < 1 {
		batch = 1
	}
	if batch > 32 {
		batch = 32
	}
	if scanner.cursor >= len(rows) {
		scanner.cursor = 0
	}
	result := make([]any, 0, batch)
	for checked := 0; checked < len(rows) && len(result) < batch; checked++ {
		row := rows[(scanner.cursor+checked)%len(rows)]
		if !strings.EqualFold(row.Status, "Running") {
			continue
		}
		result = append(result, scanOne(ctx, row))
	}
	scanner.cursor = (scanner.cursor + batch) % len(rows)
	scanner.lastRun = time.Now()
	return result
}

func listInstances(ctx context.Context) []instanceRow {
	cmd := exec.CommandContext(ctx, "incus", "list", "--format=json")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	var raw []struct{ Name, Status, Type string }
	if json.Unmarshal(output, &raw) != nil {
		return nil
	}
	rows := make([]instanceRow, 0, len(raw))
	for _, item := range raw {
		rows = append(rows, instanceRow(item))
	}
	return rows
}
func scanOne(ctx context.Context, row instanceRow) map[string]any {
	started := time.Now()
	process, pe := run(ctx, row.Name, "ps -eo pid,ppid,user,stat,pcpu,pmem,etime,comm,args --no-headers 2>/dev/null | head -n 300 || true")
	connections, ce := run(ctx, row.Name, "(ss -H -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true) | head -n 300")
	startup, se := run(ctx, row.Name, "printf '[systemd]\\n'; (systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | head -n 80 || true); printf '[cron]\\n'; (crontab -l 2>/dev/null || true); printf '[rc-local]\\n'; (test -f /etc/rc.local && sed -n '1,120p' /etc/rc.local || true); printf '[supervisor]\\n'; (command -v supervisorctl >/dev/null 2>&1 && supervisorctl status 2>/dev/null || true); printf '[pm2]\\n'; (command -v pm2 >/dev/null 2>&1 && pm2 list --no-color 2>/dev/null || true)")
	errorText := strings.TrimSpace(strings.Join([]string{pe, ce, se}, " "))
	return map[string]any{"incusId": row.Name, "capability": map[bool]string{true: "guest-agent", false: "container-exec"}[row.Type == "virtual-machine"], "success": errorText == "", "error": errorText, "processOutput": process, "connectionOutput": connections, "startupOutput": startup, "durationMs": time.Since(started).Milliseconds(), "summary": map[string]any{"processCount": lineCount(process), "connectionCount": lineCount(connections), "startupItemCount": lineCount(startup)}}
}
func run(parent context.Context, name, script string) (string, string) {
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "incus", "exec", name, "--", "sh", "-lc", script)
	output, err := cmd.CombinedOutput()
	text := string(output)
	if len(text) > 32*1024 {
		text = text[:32*1024]
	}
	if err != nil {
		return text, err.Error()
	}
	return text, ""
}
func lineCount(value string) int {
	if strings.TrimSpace(value) == "" {
		return 0
	}
	return strings.Count(value, "\n") + 1
}
