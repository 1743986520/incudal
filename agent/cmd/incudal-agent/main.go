package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"incudal-agent/internal/audit"
	"incudal-agent/internal/config"
	"incudal-agent/internal/panel"
	"incudal-agent/internal/policy"
	"incudal-agent/internal/pps"
	"incudal-agent/internal/report"
	"incudal-agent/internal/upgrade"
)

var version = "dev"
var auditScanner audit.Scanner
var lastPolicyStatus *policy.Status
var pendingAuditSnapshots []any
var policyRetryRevision string
var policyRetryDelay time.Duration
var policyNextRetryAt time.Time

const (
	initialPolicyRetryDelay = 5 * time.Second
	maxPolicyRetryDelay     = 5 * time.Minute
	policyApplyTimeout      = 45 * time.Second
	maxAuditSnapshotsPerHeartbeat = 32
)

func main() {
	configPath := flag.String("config", "/etc/incudal-agent/config.yaml", "agent config file")
	once := flag.Bool("once", false, "send one heartbeat and exit")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	syncPPS(ctx, true)

	client := panel.New(cfg)
	if *once {
		if result, err := sendHeartbeat(ctx, client, cfg.HeartbeatIntervalSeconds); err != nil {
			log.Fatalf("heartbeat: %v", err)
		} else {
			processInstructions(ctx, result)
		}
		return
	}

	log.Printf("incudal-agent started: panel=%s interval=%s", cfg.PanelURL, cfg.HeartbeatInterval)
	upgradeRunner := upgrade.DefaultRunner(cfg)
	var upgradeInProgress atomic.Bool
	if result, err := sendHeartbeat(ctx, client, cfg.HeartbeatIntervalSeconds); err != nil {
		log.Printf("heartbeat failed: %v", err)
	} else {
		processInstructions(ctx, result)
		scheduleAgentUpgrade(ctx, upgradeRunner, result, &upgradeInProgress)
	}

	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("incudal-agent stopped")
			return
		case <-ticker.C:
			syncPPS(ctx, false)
			if result, err := sendHeartbeat(ctx, client, cfg.HeartbeatIntervalSeconds); err != nil {
				log.Printf("heartbeat failed: %v", err)
			} else {
				processInstructions(ctx, result)
				scheduleAgentUpgrade(ctx, upgradeRunner, result, &upgradeInProgress)
			}
		}
	}
}

func syncPPS(ctx context.Context, logSuccess bool) {
	ppsSyncCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := pps.Sync(ppsSyncCtx); err != nil {
		log.Printf("PPS rules sync failed: %v", err)
	} else if logSuccess {
		log.Printf("PPS rules synchronized or already healthy")
	}
}

func sendHeartbeat(ctx context.Context, client *panel.Client, heartbeatIntervalSeconds int) (panel.HeartbeatResult, error) {
	payload := report.HeartbeatPayload(version, heartbeatIntervalSeconds)
	if lastPolicyStatus != nil {
		payload["networkPolicyStatus"] = policy.StatusMap(*lastPolicyStatus)
	}
	if len(pendingAuditSnapshots) > 0 {
		// Keep the batch queued until the panel has accepted the heartbeat. A
		// transport error or non-2xx response must not silently lose audit data.
		sendCount := len(pendingAuditSnapshots)
		if sendCount > maxAuditSnapshotsPerHeartbeat {
			sendCount = maxAuditSnapshotsPerHeartbeat
		}
		payload["auditSnapshots"] = append([]any(nil), pendingAuditSnapshots[:sendCount]...)
	}
	result, err := client.Heartbeat(ctx, payload)
	if err != nil {
		return result, err
	}
	if len(pendingAuditSnapshots) > 0 {
		// processInstructions runs after sendHeartbeat returns, but remove only
		// the batch that was actually sent in case a future scanner appends data
		// concurrently.
		sentCount := 0
		if snapshots, ok := payload["auditSnapshots"].([]any); ok {
			sentCount = len(snapshots)
		}
		if sentCount >= len(pendingAuditSnapshots) {
			pendingAuditSnapshots = nil
		} else if sentCount > 0 {
			pendingAuditSnapshots = pendingAuditSnapshots[sentCount:]
		}
	}
	upgradeAvailable := result.Upgrade != nil && result.Upgrade.Available
	log.Printf("heartbeat ok: status=%d latencyMs=%d upgrade=%t", result.StatusCode, result.LatencyMs, upgradeAvailable)
	return result, nil
}

func processInstructions(ctx context.Context, result panel.HeartbeatResult) {
	if result.NetworkPolicies != nil && shouldApplyNetworkPolicies(result.NetworkPolicies.Revision) {
		applyCtx, cancel := context.WithTimeout(ctx, policyApplyTimeout)
		status := policy.Apply(applyCtx, *result.NetworkPolicies)
		cancel()
		lastPolicyStatus = &status
		if status.Applied {
			policyRetryRevision = ""
			policyRetryDelay = 0
			policyNextRetryAt = time.Time{}
			log.Printf("network policies applied: revision=%s", status.Revision)
		} else {
			if policyRetryRevision != status.Revision {
				policyRetryRevision = status.Revision
				policyRetryDelay = initialPolicyRetryDelay
			} else if policyRetryDelay <= 0 {
				policyRetryDelay = initialPolicyRetryDelay
			}
			policyNextRetryAt = time.Now().Add(policyRetryDelay)
			policyRetryDelay *= 2
			if policyRetryDelay > maxPolicyRetryDelay {
				policyRetryDelay = maxPolicyRetryDelay
			}
			log.Printf("network policies failed: revision=%s error=%s", status.Revision, status.Error)
		}
	}
	if result.Monitoring != nil && result.Monitoring.Enabled {
		newSnapshots := auditScanner.Scan(ctx, *result.Monitoring)
		if len(newSnapshots) > 0 {
			pendingAuditSnapshots = append(pendingAuditSnapshots, newSnapshots...)
			log.Printf("agent audit batch collected: count=%d", len(newSnapshots))
		}
	}
}

func shouldApplyNetworkPolicies(revision string) bool {
	if lastPolicyStatus == nil || lastPolicyStatus.Revision != revision {
		return true
	}
	if lastPolicyStatus.Applied {
		return false
	}
	return !time.Now().Before(policyNextRetryAt)
}

func scheduleAgentUpgrade(ctx context.Context, runner *upgrade.Runner, result panel.HeartbeatResult, upgradeInProgress *atomic.Bool) {
	if result.Upgrade == nil || !result.Upgrade.Available {
		return
	}
	if !upgradeInProgress.CompareAndSwap(false, true) {
		log.Printf("agent upgrade already scheduled: version=%s", result.Upgrade.Version)
		return
	}

	instruction := *result.Upgrade
	log.Printf("agent upgrade scheduled: version=%s", instruction.Version)
	go func() {
		defer upgradeInProgress.Store(false)

		if delay := upgrade.RandomJitter(5 * time.Minute); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}

		upgradeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := runner.Apply(upgradeCtx, instruction, version); err != nil {
			log.Printf("agent upgrade failed: version=%s error=%v", instruction.Version, err)
			return
		}
		log.Printf("agent upgrade applied: version=%s", instruction.Version)
	}()
}
