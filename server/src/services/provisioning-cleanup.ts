import {
  claimCreatingInstanceForCleanup,
  failCreatingInstanceAndRefund,
  markCreatingInstanceProvisioned,
  type FailedProvisionResourceRollback,
  type FailedProvisionSettlementResult
} from '../db/billing-operations.js'
import {
  ensureInstanceDeleted,
  getIncusClient,
  waitForProvisioningInstanceResolution
} from '../lib/incus/index.js'
import type { Host } from '../types/database.js'

export interface FailedProvisionCleanupParams {
  instanceId: number
  instanceName: string
  host: Host
  reason: string
  resourceRollback?: FailedProvisionResourceRollback
  /** Only the stale timeout worker may reclaim an abandoned cleanup claim. */
  reclaimPendingBefore?: Date
}

export interface FailedProvisionCleanupResult {
  /** Whether this invocation claimed the instance cleanup lease. */
  claimed: boolean
  /** Whether Incus was positively confirmed to be free of the instance. */
  cleaned: boolean
  /** Whether Incus proved that the provision actually succeeded. */
  recovered?: boolean
  settlement?: FailedProvisionSettlementResult
  error?: unknown
}

/**
 * The only path that may settle a failed provision.
 *
 * Claiming happens in the database first, but the row remains `creating` and
 * is marked as cleanup-pending. The instance can therefore neither be retried
 * nor promoted back to `running` while the external cleanup is in flight.
 * Settlement is attempted only after ensureInstanceDeleted() confirms 404.
 */
export async function cleanupAndSettleFailedProvision(
  params: FailedProvisionCleanupParams
): Promise<FailedProvisionCleanupResult> {
  let client: Awaited<ReturnType<typeof getIncusClient>>

  // Resolve the external operation before claiming failure. A normal
  // Running/Stopped instance means the timeout was a false negative: keep
  // the charge and reservations, and make the database reflect reality.
  try {
    client = await getIncusClient(params.host)
    const resolution = await waitForProvisioningInstanceResolution(client, params.instanceName)
    if (resolution.kind === 'present') {
      const recovered = await markCreatingInstanceProvisioned(params.instanceId, resolution.status)
      if (recovered) return { claimed: false, cleaned: false, recovered: true }
    }
  } catch (error) {
    return { claimed: false, cleaned: false, error }
  }

  let claimed: boolean
  try {
    claimed = await claimCreatingInstanceForCleanup(params.instanceId, {
      reclaimPendingBefore: params.reclaimPendingBefore
    })
  } catch (error) {
    return { claimed: false, cleaned: false, error }
  }

  if (!claimed) {
    return { claimed: false, cleaned: false }
  }

  try {
    // Re-check after the database claim. The create worker may have finished
    // between the first external check and the claim transaction.
    const resolution = await waitForProvisioningInstanceResolution(client, params.instanceName)
    if (resolution.kind === 'present') {
      const recovered = await markCreatingInstanceProvisioned(params.instanceId, resolution.status)
      if (recovered) return { claimed: true, cleaned: false, recovered: true }
      throw new Error(`Instance ${params.instanceId} changed state while reconciling provisioning`)
    }

    await ensureInstanceDeleted(client, params.instanceName)
  } catch (error) {
    // Keep the cleanup-pending claim and all billing/resource reservations.
    // The timeout worker will retry this instance after the next stale window.
    return { claimed: true, cleaned: false, error }
  }

  try {
    const settlement = await failCreatingInstanceAndRefund(
      params.instanceId,
      params.reason,
      params.resourceRollback
    )
    return { claimed: true, cleaned: true, settlement }
  } catch (error) {
    // Incus is already confirmed absent. The persistent claim remains set so
    // a later retry can finish the DB settlement without deleting/refunding a
    // second time.
    return { claimed: true, cleaned: true, error }
  }
}
