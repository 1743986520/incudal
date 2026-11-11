/** Durable, retryable instance deletion. A PostgreSQL session lock covers the
 * external Incus/Caddy calls; the final state change and resource release are
 * committed together, and billing settlement remains independently retryable. */
import { prisma } from '../db/prisma.js'
import { Pool } from 'pg'
import type { Instance, Prisma } from '@prisma/client'
import * as db from '../db/index.js'
import { advisoryTransactionLock, INSTANCE_OPERATION_LOCK_NAMESPACE } from '../db/advisory-locks.js'
import { decrementHostResourceCounters } from '../db/quota-operations.js'
import { readReservationEvidenceForUpdate, recordReservationRelease } from '../db/resource-reservation-evidence.js'
import { createCaddyClient } from '../lib/caddy-client.js'
import { ensureInstanceDeleted, getIncusClient } from '../lib/incus/index.js'
import { createLog } from '../db/logs.js'
import { sendNotification } from '../lib/notifier.js'
import { withDomainRemoteOperationLock } from './instance-remote-operation-lock.js'
import { runWithRemoteOperationAbortSignal, throwIfRemoteOperationAborted } from './remote-operation-abort.js'
import { canFinalizeExpiredUserDestroy } from './expired-destroy-eligibility.js'

const DELETION_SESSION_LOCK_NAMESPACE = 4112
const NAT_MODES = ['nat', 'nat_ipv6', 'nat_ipv6_nat', 'ipv6_nat', 'ipv6_only']
export const pendingDeletionRecoveryWhere: Prisma.InstanceWhereInput = {
  status: 'deleting',
  OR: [{ host: { status: 'online' } }, { deletionRemoteDeleted: true }],
  retiredTombstone: { is: null }
}
// Separate from Prisma's pool: even DB_POOL_MAX=1 can make progress while a
// session lock is held across an external operation.
const deletionLockPool = new Pool({ connectionString: process.env.DATABASE_URL, max: 4, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30000 })

type DeletionHost = NonNullable<Awaited<ReturnType<typeof db.getHostById>>>
export interface PendingDeletionRemoteOperations {
  ensureDeleted(host: DeletionHost, instance: Instance): Promise<void>
  deleteProxySite(host: DeletionHost, domain: string): Promise<void>
}

const defaultRemoteOperations: PendingDeletionRemoteOperations = {
  async ensureDeleted(host, instance) {
    const client = await getIncusClient(host)
    await ensureInstanceDeleted(client, instance.incusId)
  },
  async deleteProxySite(host, domain) {
    const address = host.nat_public_ip || host.ip_address
    if (!address || !host.caddy_username || !host.caddy_password) throw new Error('Caddy configuration unavailable')
    const caddy = createCaddyClient({ host: address, port: host.caddy_port || 8444, username: host.caddy_username, password: host.caddy_password })
    await caddy.deleteSite(domain)
  }
}

export async function processPendingInstanceDeletion(instanceId: number, remote: PendingDeletionRemoteOperations = defaultRemoteOperations): Promise<{ refundAmount: number } | null> {
  const connection = await deletionLockPool.connect()
  let locked = false
  let connectionFailed = false
  const controller = new AbortController()
  const onError = () => {
    connectionFailed = true
    controller.abort(new Error('Pending-deletion lock connection failed'))
  }
  connection.on('error', onError)
  connection.on('end', onError)
  try {
    const result = await connection.query<{ locked: boolean }>(
      'SELECT pg_try_advisory_lock($1, $2) AS locked', [DELETION_SESSION_LOCK_NAMESPACE, instanceId]
    )
    locked = result.rows[0]?.locked === true
    if (!locked) return null
    return await runWithRemoteOperationAbortSignal(controller.signal, async () => {

    const instance = await prisma.instance.findUnique({ where: { id: instanceId } })
    if (!instance || instance.status !== 'deleting') return null
    // Retirement takes the same session-lock namespace. The protected FK-backed
    // tombstone, not the independently removable audit log, is the fence.
    if (await prisma.retiredInstanceTombstone.findUnique({ where: { instanceId }, select: { instanceId: true } })) return null
    // Advance the cursor even for cases requiring human reconciliation so
    // they cannot starve every later eligible deletion in the recovery queue.
    await prisma.instance.updateMany({ where: { id: instanceId, status: 'deleting' }, data: { deletionLastAttemptAt: new Date() } })
    if (!instance.deletionOriginalStatus || instance.deletionOriginalStatus === 'creating' || instance.provisioningCleanupPending) {
      throw new Error('Instance resource reservation state is unknown')
    }
    const expiredUserDestroy = canFinalizeExpiredUserDestroy(instance)
    if (instance.deletionBillingMode === 'user_destroy' && !expiredUserDestroy) {
      // A stale pre-stop traffic snapshot cannot prove refund eligibility. A
      // manual reconciliation must establish final usage before any remote
      // deletion, billing or release; do not infer it from stopped/error.
      throw new Error('User destruction requires final traffic reconciliation')
    }
    if (instance.trafficBillingMode === 'usage') {
      throw new Error('Usage-based traffic requires final settlement before deletion')
    }
    if (instance.billingMode === 'hourly') {
      throw new Error('Hourly billing requires final settlement before deletion')
    }
    const host = await db.getHostById(instance.hostId)
    if (!host) throw new Error('Source host not found')

    // Preserve the first quotation across retries; the balance transaction caps
    // it against the remaining refundable value at settlement time.
    let refund = instance.deletionRefundableValue === null ? null : Number(instance.deletionRefundableValue)
    if (instance.deletionBillingPending && instance.deletionBillingMode === 'privileged_delete' && refund === null) {
      const quote = await db.calculateInstanceRefund(instance, instance.deletionRequestedAt ?? undefined)
      refund = quote.isPaid ? quote.refundAmount : 0
      await prisma.instance.updateMany({
        where: { id: instanceId, status: 'deleting', deletionRefundableValue: null },
        data: { deletionRefundableValue: refund }
      })
    }

    if (!instance.deletionRemoteDeleted) {
      if (host.status !== 'online') throw new Error('Source host is unavailable')
      await remote.ensureDeleted(host, instance)
      throwIfRemoteOperationAborted()
      const marked = await prisma.instance.updateMany({
        where: { id: instanceId, status: 'deleting' },
        data: { deletionRemoteDeleted: true }
      })
      if (marked.count !== 1) throw new Error('Deletion claim lost after remote deletion')
    }

    // Do not free an address while a Caddy route still points at it.
    const sites = await prisma.proxySite.findMany({ where: { instanceId } })
    if (sites.length && (!host.caddy_enabled || !host.caddy_username || !host.caddy_password || !(host.nat_public_ip || host.ip_address))) {
      throw new Error('Caddy site removal cannot be confirmed')
    }
    for (const site of sites) {
      // The instance lock is already held. Always take the domain lock second,
      // then re-read the identity so an old snapshot cannot delete a new site.
      const siteLock = await withDomainRemoteOperationLock(site.domain, async () => {
        const current = await prisma.proxySite.findUnique({ where: { id: site.id } })
        if (!current || current.instanceId !== instanceId || current.hostId !== host.id || current.domain !== site.domain) {
          throw new Error('Caddy site identity changed during deletion')
        }
        await remote.deleteProxySite(host, current.domain)
        throwIfRemoteOperationAborted()
      })
      if (!siteLock.acquired) throw new Error('Caddy domain operation is in progress')
    }

    throwIfRemoteOperationAborted()
    let refundAmount = 0
    if (instance.deletionBillingPending) {
      if (instance.deletionBillingMode === 'privileged_delete') {
        refundAmount = await db.settlePrivilegedDeletionBilling({
          instance: { id: instance.id, userId: instance.userId, hostId: instance.hostId, name: instance.name },
          requestedRefundAmount: refund ?? 0,
          remark: `托管实例被删除退款：${instance.name}`
        })
      } else if (expiredUserDestroy) {
        const settled = await db.settleUserDestroyBilling({
          requestUserId: instance.userId,
          instance: { id: instance.id, userId: instance.userId, hostId: instance.hostId, name: instance.name },
          refundableValue: 0,
          feeWaiver: instance.deletionFeeWaiver
        })
        refundAmount = settled.refundAmount
      } else throw new Error('Invalid pending deletion billing mode')
    }

    // Atomic CAS + resource release: a second worker or crash cannot release twice.
    const finished = await prisma.$transaction(async tx => {
      await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)
      const claimed = await tx.instance.updateMany({
        where: { id: instanceId, status: 'deleting', deletionRemoteDeleted: true, deletionBillingPending: false },
        data: { status: 'deleted', version: { increment: 1 } }
      })
      if (claimed.count !== 1) return false
      await tx.snapshot.deleteMany({ where: { instanceId } })
      await tx.backup.deleteMany({ where: { instanceId } })
      await tx.portMapping.deleteMany({ where: { instanceId } })
      await tx.proxySite.deleteMany({ where: { instanceId } })
      await tx.snapshotPolicy.deleteMany({ where: { instanceId } })
      await tx.backupPolicy.deleteMany({ where: { instanceId } })
      await tx.trafficSnapshot.deleteMany({ where: { instanceId } })
      await tx.dailyTraffic.deleteMany({ where: { instanceId } })
      await tx.ipAddress.deleteMany({ where: { instanceId } })
      await tx.ipv6Subnet.deleteMany({ where: { instanceId } })
      await tx.restoreTask.deleteMany({ where: { instanceId, status: { in: ['COMPLETED', 'FAILED'] } } })
      await tx.backupUploadTask.deleteMany({ where: { instanceId, status: { in: ['COMPLETED', 'FAILED'] } } })
      await tx.instanceTask.deleteMany({ where: { instanceId, status: { in: ['COMPLETED', 'FAILED'] } } })
      await tx.instanceTransfer.updateMany({ where: { instanceId, status: 'pending' }, data: { status: 'cancelled', cancelledAt: new Date() } })
      const reservationBefore = await readReservationEvidenceForUpdate(tx, instanceId)
      const releasedResources = {
        hostId: instance.hostId, cpu: instance.cpu, memory: instance.memory, disk: instance.disk,
        portCount: NAT_MODES.includes(instance.networkMode) ? instance.portLimit ?? 0 : 0
      }
      if (reservationBefore.state === 'unknown') throw new Error('Instance resource reservation evidence is unavailable or stale')
      const amounts = reservationBefore.amounts
      if (amounts.hostId !== releasedResources.hostId || amounts.cpu !== releasedResources.cpu
        || amounts.memory !== releasedResources.memory || amounts.disk !== releasedResources.disk
        || amounts.portCount !== releasedResources.portCount) {
        throw new Error('Instance resource reservation evidence does not match deletion')
      }
      if (reservationBefore.state === 'reserved') {
        await decrementHostResourceCounters(tx, releasedResources)
        await recordReservationRelease(tx, reservationBefore, { ...releasedResources, instanceId })
        const after = await readReservationEvidenceForUpdate(tx, instanceId)
        if (after.state !== 'released') throw new Error('Instance resource release could not be verified')
      }
      throwIfRemoteOperationAborted()
      return true
    })
    if (!finished) return null

    // Notifications and logs are not allowed to undo an already finalized deletion.
    try {
      // A system/operator request has no authenticated panel user; do not
      // falsely attribute its finalization to the instance owner.
      await createLog(instance.deletionRequestedById, 'instance', 'instance.delete',
        `Deleted instance "${instance.name}" [host: ${host.name}]`, 'success', { instanceId })
      await sendNotification(instance.userId, instance.deletionReason ? 'instance_deleted_by_host_owner' : 'instance_deleted', {
        instanceName: instance.name, hostName: host.name, ...(instance.deletionReason ? { deleteReason: instance.deletionReason } : {})
      })
      if (instance.packageId) {
        const { sendReleaseNotification } = await import('../lib/release-notifier.js')
        void sendReleaseNotification({ packageId: instance.packageId, cpu: instance.cpu, memory: instance.memory, source: '实例删除' }).catch(() => {})
      }
    } catch (error) { console.error(`[PendingDeletion] Post-delete notification failed for ${instanceId}:`, error) }
    return { refundAmount }
    })
  } finally {
    connection.removeListener('error', onError)
    connection.removeListener('end', onError)
    if (locked && !connectionFailed) {
      try { await connection.query('SELECT pg_advisory_unlock($1, $2)', [DELETION_SESSION_LOCK_NAMESPACE, instanceId]) }
      catch { connectionFailed = true }
    }
    connection.release(connectionFailed)
  }
}

export async function runPendingInstanceDeletionRecovery(): Promise<void> {
  const pending = await prisma.instance.findMany({
    where: pendingDeletionRecoveryWhere,
    select: { id: true }, orderBy: { deletionLastAttemptAt: { sort: 'asc', nulls: 'first' } }, take: 100
  })
  for (const instance of pending) {
    try { await processPendingInstanceDeletion(instance.id) }
    catch (error) { console.warn(`[PendingDeletion] Instance ${instance.id} remains pending:`, error) }
  }
}
