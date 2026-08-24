import pLimit from 'p-limit'
import { getAllHosts, updateHostStatus } from '../db/hosts.js'
import { getIncusClient, removeIncusClient } from '../lib/incus/index.js'

const CHECK_INTERVAL_MS = 60 * 1000
const FAILURE_THRESHOLD = 3
// Recovery is deliberately slower than failure detection so a flapping Incus
// endpoint cannot briefly re-enter package allocation after two lucky probes.
const RECOVERY_THRESHOLD = 5
const CHECK_CONCURRENCY = 4

interface ProbeState {
  failures: number
  successes: number
}

const probeStates = new Map<number, ProbeState>()
let monitorStarted = false
let checkRunning = false

function getProbeState(hostId: number): ProbeState {
  const state = probeStates.get(hostId) ?? { failures: 0, successes: 0 }
  probeStates.set(hostId, state)
  return state
}

async function probeHost(host: Awaited<ReturnType<typeof getAllHosts>>[number]): Promise<void> {
  const state = getProbeState(host.id)

  if (!host.cert_path || !host.key_path) {
    state.failures = Math.min(state.failures + 1, FAILURE_THRESHOLD)
    state.successes = 0
  } else {
    try {
      const client = await getIncusClient(host)
      await client.getServerInfo()
      state.successes++
      state.failures = 0
    } catch (error) {
      state.failures = Math.min(state.failures + 1, FAILURE_THRESHOLD)
      state.successes = 0

      // Do not keep returning a stale pooled client on the next probe.
      await removeIncusClient(host.id).catch(() => {})

      // Once a host is offline, keep probing for recovery without repeating
      // the same connectivity warning every minute.
      if (host.status === 'online' || state.failures < FAILURE_THRESHOLD) {
        const message = error instanceof Error ? error.message : String(error)
        console.warn(
          `[HostHealth] Probe failed for ${host.name}(#${host.id}) ` +
          `${state.failures}/${FAILURE_THRESHOLD}: ${message}`
        )
      }
    }
  }

  if (host.status === 'online' && state.failures >= FAILURE_THRESHOLD) {
    await updateHostStatus(host.id, 'offline')
    console.error(
      `[HostHealth] Host ${host.name}(#${host.id}) marked offline after ` +
      `${state.failures} consecutive failed probes`
    )
    return
  }

  if (host.status === 'offline' && state.successes >= RECOVERY_THRESHOLD) {
    await updateHostStatus(host.id, 'online')
    console.log(
      `[HostHealth] Host ${host.name}(#${host.id}) restored online after ` +
      `${state.successes} consecutive successful probes`
    )
  }
}

export async function runHostHealthCheck(): Promise<void> {
  if (checkRunning) {
    console.warn('[HostHealth] Previous check is still running; skipped overlapping run')
    return
  }

  checkRunning = true
  try {
    const hosts = await getAllHosts()
    const eligibleHosts = hosts.filter(host => host.status !== 'maintenance')
    const eligibleIds = new Set(eligibleHosts.map(host => host.id))

    for (const hostId of probeStates.keys()) {
      if (!eligibleIds.has(hostId)) {
        probeStates.delete(hostId)
      }
    }

    const limit = pLimit(CHECK_CONCURRENCY)
    await Promise.all(eligibleHosts.map(host => limit(() => probeHost(host))))
  } catch (error) {
    console.error('[HostHealth] Check failed:', error)
  } finally {
    checkRunning = false
  }
}

export function startHostHealthMonitor(): void {
  if (monitorStarted) return
  monitorStarted = true

  void runHostHealthCheck()
  setInterval(() => {
    void runHostHealthCheck()
  }, CHECK_INTERVAL_MS)

  console.log(
    `[HostHealth] Monitor started ` +
    `(interval=${CHECK_INTERVAL_MS / 1000}s, offline=${FAILURE_THRESHOLD} failures, ` +
    `online=${RECOVERY_THRESHOLD} successes)`
  )
}
