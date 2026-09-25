import {
  claimCreatingInstanceForCleanup,
  failCreatingInstanceAndRefund,
  type FailedProvisionResourceRollback,
  type FailedProvisionSettlementResult
} from '../db/billing-operations.js'
import { ensureInstanceDeleted, getIncusClient } from '../lib/incus/index.js'
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
    const client = await getIncusClient(params.host)
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
